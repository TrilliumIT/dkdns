package main

import (
	"fmt"
	"net"

	log "github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
)

func handle(w dns.ResponseWriter, r *dns.Msg) {
	log.WithField("Message", r).Debug("Handling DNS Request")
	var (
		rr  dns.RR
		str string
	)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = compress

	name := r.Question[0].Name

	rr = &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
		A:   net.ParseIP("192.168.5.5"),
	}

	str = "bleh"

	t := &dns.TXT{
		Hdr: dns.RR_Header{Name: dom, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
		Txt: []string{str},
	}

	switch r.Question[0].Qtype {
	case dns.TypeTXT:
		m.Answer = append(m.Answer, t)
		m.Extra = append(m.Extra, rr)
	case dns.TypeAAAA, dns.TypeA:
		m.Answer = append(m.Answer, rr)
		m.Extra = append(m.Extra, t)
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
