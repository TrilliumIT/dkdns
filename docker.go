package main

import (
	"net/http"

	"github.com/docker/docker/pkg/tlsconfig"
	dockerclient "github.com/docker/engine-api/client"
)

func newDockerTLSClient(host, version, ca, cert, key string, verify bool) (*dockerclient.Client, error) {
	var client *http.Client
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

	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsc,
		},
	}

	return dockerclient.NewClient(host, version, client, nil)
}
