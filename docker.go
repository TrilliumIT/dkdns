package main

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/clinta/docker-events"
	dockertypes "github.com/docker/docker/api/types"
	dockerevents "github.com/docker/docker/api/types/events"
	dockerclient "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/tlsconfig"
)

const dockerVersion = "v1.23"

var (
	containers    map[string]containerData
	containerlock sync.RWMutex
)

type containerData struct {
	Cjson        dockertypes.ContainerJSON
	DockerHostID string
}

func monDocker(dockerEndpoints []string, ca, cert, key string, verify bool, resync int) {
	containers = make(map[string]containerData)
	records = make(map[string][]net.IP)
	rev_records = make(map[string]string)

	for _, e := range dockerEndpoints {
		log.WithField("Docker Endpoint", e).Debug("Starting docker monitor")
		var (
			err    error
			client *http.Client
		)

		if ca != "" && !strings.HasPrefix(e, "unix://") {
			client, err = newHttpTlsClient(ca, cert, key, verify)
			if err != nil {
				log.WithError(err).Error("Failed to create http client")
			}
		}

		dockerClient, err := dockerclient.NewClient(e, dockerVersion, client, nil)
		if err != nil {
			log.WithError(err).Error("Error connecting to docker socket")
			continue
		}
		go dockerWatch(dockerClient, resync)
	}
}

func syncAllContainers(dockerClient *dockerclient.Client, cxt context.Context, hostID string) error {
	dockerContainers, err := dockerClient.ContainerList(cxt, dockertypes.ContainerListOptions{})
	if err != nil {
		return err
	}
	containerlock.Lock()
	for _, dc := range dockerContainers {
		cjson, err := dockerClient.ContainerInspect(context.Background(), dc.ID)
		if err != nil {
			log.WithError(err).WithField("Container ID", dc.ID).Error("Error inspecting container")
			continue
		}
		containers[dc.ID] = containerData{Cjson: cjson, DockerHostID: hostID}
	}
	for id, c := range containers {
		if c.DockerHostID != hostID {
			continue
		}
		r := false
		for _, dc := range dockerContainers {
			if c.Cjson.ID == dc.ID {
				r = true
				break
			}
		}
		if !r {
			delete(containers, id)
		}
	}
	containerlock.Unlock()
	go updateRecords()
	return nil
}

func dockerWatch(dockerClient *dockerclient.Client, resync int) {
	for {
		cxt, cancel := context.WithCancel(context.Background())
		// Get host ID
		dockerInfo, err := dockerClient.Info(cxt)
		if err != nil {
			log.WithError(err).Error("Error getting host id")
			cancel()
			time.Sleep(2 * time.Second)
			continue
		}
		hostID := dockerInfo.ID
		// on startup populate containers
		err = syncAllContainers(dockerClient, cxt, hostID)
		if err != nil {
			log.WithError(err).Error("Error syncing all containers")
			cancel()
			time.Sleep(2 * time.Second)
			continue
		}

		// Start monitoring docker events
		dockerEventErr := events.Monitor(cxt, dockerClient, dockertypes.EventsOptions{}, func(event dockerevents.Message) {
			if event.Type != "network" {
				return
			}
			cid, ok := event.Actor.Attributes["container"]
			if !ok {
				//we don't need to go any further because this event does not involve a container
				return
			}
			if event.Action != "connect" && event.Action != "disconnect" {
				// Only change dns on network events
				return
			}
			log.WithField("Container", cid).Debug("Docker network event recieved")

			// now we need to inspect and update all the IP information associated with this container
			cjson, err := dockerClient.ContainerInspect(context.Background(), cid)
			if err != nil {
				log.WithError(err).WithField("Container ID", cid).Error("Error inspecting container")
			}
			containerlock.Lock()
			defer containerlock.Unlock()
			containers[cid] = containerData{Cjson: cjson, DockerHostID: hostID}
			go updateRecords()
			return
		})

		endResync := make(chan struct{})
		if resync != 0 {
			go func() {
				t := time.NewTicker(time.Duration(resync) * time.Second)
				for {
					err = syncAllContainers(dockerClient, cxt, hostID)
					if err != nil {
						log.WithError(err).Error("Error syncing all containers")
					}
					select {
					case <-t.C:
						continue
					case <-endResync:
						t.Stop()
						break
					}
				}
			}()
		}

		// wait for an error from the monitoring, if we get one. Log and start over.
		err = <-dockerEventErr
		log.WithError(err).Error("Error from docker event subscription")
		close(endResync)
		cancel()
		// cleanup containers
		containerlock.Lock()
		for id, c := range containers {
			if c.DockerHostID == hostID {
				delete(containers, id)
			}
		}
		containerlock.Unlock()
	}
}

func newHttpTlsClient(ca, cert, key string, verify bool) (*http.Client, error) {
	options := tlsconfig.Options{
		CAFile:             ca,
		CertFile:           cert,
		KeyFile:            key,
		InsecureSkipVerify: verify,
	}
	tlsc, err := tlsconfig.Client(options)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsc,
		},
	}, nil
}
