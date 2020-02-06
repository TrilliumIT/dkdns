package main

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	dockertypes "github.com/docker/docker/api/types"
	dockerclient "github.com/docker/docker/client"
	"github.com/docker/go-connections/tlsconfig"
	log "github.com/sirupsen/logrus"
)

const dockerVersion = "v1.23"

var (
	containers    map[string]containerData
	containerlock sync.RWMutex
)

type containerData struct {
	Cjson        *dockertypes.ContainerJSON
	DockerHostID string
}

func cJsonEqual(a, b *dockertypes.ContainerJSON) bool {
	if (a == nil) && (b == nil) {
		return true
	}
	if (a == nil) != (b == nil) {
		return false
	}
	if a.Name != b.Name {
		return false
	}
	if a.Config.Hostname != b.Config.Hostname {
		return false
	}
	if a.Config.Labels[aLabel] != b.Config.Labels[aLabel] {
		return false
	}
	if (a.NetworkSettings == nil) && (b.NetworkSettings == nil) {
		return true
	}
	if (a.NetworkSettings == nil) != (b.NetworkSettings == nil) {
		return false
	}
	if len(a.NetworkSettings.Networks) != len(b.NetworkSettings.Networks) {
		return false
	}
	for n := range a.NetworkSettings.Networks {
		if (a.NetworkSettings.Networks[n] == nil) && (b.NetworkSettings.Networks[n] == nil) {
			continue
		}
		if (a.NetworkSettings.Networks[n] == nil) != (b.NetworkSettings.Networks[n] == nil) {
			return false
		}
		if a.NetworkSettings.Networks[n].IPAddress != b.NetworkSettings.Networks[n].IPAddress {
			return false
		}
	}
	return true
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

func syncAllContainers(dockerClient *dockerclient.Client, cxt context.Context, hostID string) (bool, error) {
	changes := false
	dockerContainers, err := dockerClient.ContainerList(cxt, dockertypes.ContainerListOptions{})
	if err != nil {
		return true, err
	}
	containerlock.Lock()
	defer containerlock.Unlock()
	for _, dc := range dockerContainers {
		cjson, err := dockerClient.ContainerInspect(context.Background(), dc.ID)
		if err != nil {
			log.WithError(err).WithField("Container ID", dc.ID).Error("Error inspecting container")
			continue
		}
		if !changes {
			changes = !cJsonEqual(containers[dc.ID].Cjson, &cjson)
		}
		containers[dc.ID] = containerData{Cjson: &cjson, DockerHostID: hostID}
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
			changes = true
			delete(containers, id)
		}
	}
	go updateRecords()
	return changes, nil
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
		_, err = syncAllContainers(dockerClient, cxt, hostID)
		if err != nil {
			log.WithError(err).Error("Error syncing all containers")
			cancel()
			time.Sleep(2 * time.Second)
			continue
		}

		// Start monitoring docker events
		dockerEvent, dockerEventErr := dockerClient.Events(cxt, dockertypes.EventsOptions{})
		t := time.NewTimer(time.Duration(resync) * time.Second)
		go func() {
			for event := range dockerEvent {
				t.Reset(time.Duration(resync) * time.Second)
				if event.Type != "network" {
					continue
				}
				cid, ok := event.Actor.Attributes["container"]
				if !ok {
					//we don't need to go any further because this event does not involve a container
					continue
				}
				if event.Action != "connect" && event.Action != "disconnect" {
					// Only change dns on network events
					continue
				}
				log.WithField("Container", cid).Debug("Docker network event recieved")

				// now we need to inspect and update all the IP information associated with this container
				r := false
				cjson, err := dockerClient.ContainerInspect(context.Background(), cid)
				if err != nil {
					log.WithError(err).WithField("Container ID", cid).Error("Error inspecting container")
					r = true
				}
				if !r && cjson.NetworkSettings == nil {
					r = true
				}
				if !r && len(cjson.NetworkSettings.Networks) == 0 {
					r = true
				}
				containerlock.Lock()
				if r {
					delete(containers, cid)
				} else {
					containers[cid] = containerData{Cjson: &cjson, DockerHostID: hostID}
				}
				containerlock.Unlock()
				go updateRecords()
			}
		}()

		endResync := make(chan struct{})
		if resync != 0 {
			go func() {
				for {
					changes, err := syncAllContainers(dockerClient, cxt, hostID)
					if err != nil {
						log.WithError(err).Error("Error syncing all containers")
						cancel()
						return
					}
					if changes {
						log.Error("Resync caused changes, reconnecting to events")
						cancel()
						return
					}
					select {
					case <-t.C:
						t.Reset(time.Duration(resync) * time.Second)
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
		if err != nil {
			log.WithError(err).Error("Error from docker event subscription")
		}
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
