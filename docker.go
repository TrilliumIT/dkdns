package main

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/clinta/docker-events"
	dockertypes "github.com/docker/docker/api/types"
	dockerevents "github.com/docker/docker/api/types/events"
	dockerclient "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/tlsconfig"
)

const dockerVersion = "v1.23"

var (
	containers    map[string]dockertypes.ContainerJSON
	containerlock sync.RWMutex
)

func monDocker(dockerEndpoints []string, ca, cert, key string, verify bool) {
	containers = make(map[string]dockertypes.ContainerJSON)
	records = make(map[string][]net.IP)

	for _, e := range dockerEndpoints {
		log.WithField("Docker Endpoint", e).Debug("Starting docker monitor")
		var (
			err    error
			client *http.Client
		)

		switch {
		case strings.HasPrefix(e, "https://"):
			client, err = newHttpTlsClient(ca, cert, key, verify)
			if err != nil {
				log.WithError(err).Error("Error initializing tls client")
			}
		case strings.HasPrefix(e, "http://"):
			client = &http.Client{}
		}
		dockerClient, err := dockerclient.NewClient(e, dockerVersion, client, nil)
		if err != nil {
			log.WithError(err).Error("Error connecting to docker socket")
			continue
		}
		go dockerWatch(dockerClient, context.Background())
		// on startup populate containers
		dockerContainers, err := dockerClient.ContainerList(context.Background(), dockertypes.ContainerListOptions{})
		if err != nil {
			log.WithError(err).Error("Error getting container list")
			continue
		}
		containerlock.Lock()
		for _, dc := range dockerContainers {
			cjson, err := dockerClient.ContainerInspect(context.Background(), dc.ID)
			if err != nil {
				log.WithError(err).WithField("Container ID", dc.ID).Error("Error inspecting container")
			}
			containers[dc.ID] = cjson
		}
		containerlock.Unlock()
		go updateRecords()
	}
}

func dockerWatch(dockerClient *dockerclient.Client, ctx context.Context) {
	dockerEventErr := events.Monitor(ctx, dockerClient, dockertypes.EventsOptions{}, func(event dockerevents.Message) {
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
		containers[cid] = cjson
		go updateRecords()
		return
	})
	for {
		err := <-dockerEventErr
		log.WithError(err).Error("Error from docker event subscription")
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
