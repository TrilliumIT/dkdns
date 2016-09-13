package main

import (
	"os"
	"os/signal"
	"syscall"

	log "github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"github.com/urfave/cli"
)

const version = "0.1"

var (
	compress bool
	dom      string
)

func main() {
	app := cli.NewApp()
	app.Name = "dkdns"
	app.Usage = "Docker Dynamic DNS"
	app.Version = version
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug, d",
			Usage: "Enable debugging.",
		},
		cli.StringFlag{
			Name:  "domain, dom",
			Value: "dkdns.",
			Usage: "Top level domain to serve.",
		},
		cli.BoolFlag{
			Name:  "compress",
			Usage: "Compress dns replies.",
		},
		cli.StringSliceFlag{
			Name:  "docker-endpoint",
			Usage: "URL to docker endpoint(s)",
			Value: &cli.StringSlice{"unix:///var/run/docker.sock"},
		},
		cli.StringFlag{
			Name:  "ca",
			Usage: "Path to docker CA if using TLS",
		},
		cli.StringFlag{
			Name:  "cert",
			Usage: "Path to docker cert if using TLS",
		},
		cli.StringFlag{
			Name:  "key",
			Usage: "Path to docker key if using TLS",
		},
		cli.BoolFlag{
			Name:  "no-validate",
			Usage: "Don't validate ssl connections.",
		},
	}
	app.Action = Run
	err := app.Run(os.Args)
	if err != nil {
		panic(err)
	}
}

func Run(ctx *cli.Context) error {
	log.SetFormatter(&log.TextFormatter{
		//ForceColors: false,
		//DisableColors: true,
		DisableTimestamp: false,
		FullTimestamp:    true,
	})

	if ctx.Bool("debug") {
		log.SetLevel(log.DebugLevel)
		log.Info("Debug logging enabled")
	}
	log.WithField("Level", log.GetLevel()).Info("Log level set")

	compress = ctx.Bool("compress")
	dom = ctx.String("domain")

	log.WithField("Domain", dom).Debug("Domain set")
	log.WithField("Compress", compress).Debug("Compression set")

	dns.HandleFunc(dom, handle)
	go serve("tcp")
	go serve("udp")

	go monDocker(ctx.StringSlice("docker-endpoint"), ctx.String("ca"), ctx.String("cert"), ctx.String("key"), !ctx.Bool("no-validate"))

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Infof("Signal (%s) received, stopping\n", s)
	for _, cf := range cancelFuncs {
		cf()
	}
	return nil
}
