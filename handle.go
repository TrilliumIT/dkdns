package main

import (
	"fmt"
	"net"
	"strings"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
)

var (
	records    map[string][]net.IP
	recordLock sync.RWMutex
)

func updateRecords() {
	log.Debug("Updating records")
	containerlock.RLock()
	defer containerlock.RUnlock()
	recordLock.Lock()
	defer recordLock.Unlock()
	records = make(map[string][]net.IP)
	for _, cjson := range containers {
		hn := cjson.Config.Hostname
		hn = strings.TrimSuffix(strings.TrimRight(hn, "."), strings.TrimRight(dom, "."))
		hn = hn + dom
		for _, es := range cjson.NetworkSettings.Networks {
			records[hn] = append(records[hn], net.ParseIP(es.IPAddress))
		}
	}
	log.WithField("Records", len(records)).Debug("Records updated")
}

func handle(w dns.ResponseWriter, r *dns.Msg) {
	log.WithField("Message", r).Debug("Handling DNS Request")
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = compress

	for _, q := range r.Question {
		if q.Qtype != dns.TypeA || q.Qtype != dns.TypeAAAA {
			continue
		}
		func() {
			recordLock.RLock()
			defer recordLock.RUnlock()
			for _, ip := range records[q.Name] {
				if ip.To4() == nil {
					rr := &dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
							Ttl:    0,
						},
						AAAA: ip,
					}
					if q.Qtype == dns.TypeAAAA {
						m.Answer = append(m.Answer, rr)
					} else {
						m.Extra = append(m.Extra, rr)
					}
				} else {
					rr := &dns.A{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    0,
						},
						A: ip,
					}
					if q.Qtype == dns.TypeA {
						m.Answer = append(m.Answer, rr)
					} else {
						m.Extra = append(m.Extra, rr)
					}
				}
			}
		}()
	}

	log.WithField("Response", m).Debug("Sending DNS Response")
	w.WriteMsg(m)
}

func serve(proto string) {
	server := &dns.Server{Addr: ":8053", Net: proto, TsigSecret: nil}
	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("Failed to setup the "+proto+" server: %s\n", err.Error())
	}
}
