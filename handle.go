package main

import (
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

var (
	records     map[string][]net.IP
	recordLock  sync.RWMutex
	rev_records map[string]string
)

const aLabel = "DKDNS_A"

func appendIfMissing(s []net.IP, i net.IP) []net.IP {
	for _, e := range s {
		if e.Equal(i) {
			return s
		}
	}
	return append(s, i)
}

func updateRecords() {
	log.Debug("Updating records")
	containerlock.RLock()
	defer containerlock.RUnlock()
	recordLock.Lock()
	defer recordLock.Unlock()
	for k := range records {
		delete(records, k)
	}
	for _, cdata := range containers {
		cjson := cdata.Cjson
		for _, es := range cjson.NetworkSettings.Networks {
			if es.IPAddress != "" {
				ip := net.ParseIP(es.IPAddress)
				var rev string
				if al, ok := cjson.Config.Labels[aLabel]; ok {
					for _, l := range strings.Split(al, ",") {
						ln := fullyQualify(l)
						records[ln] = appendIfMissing(records[ln], ip)
						rev = ln
					}
				}
				if regContainerName {
					cn := fullyQualify(cjson.Name)
					records[cn] = appendIfMissing(records[cn], ip)
					rev = cn
				}
				if regHostName {
					hn := fullyQualify(cjson.Config.Hostname)
					records[hn] = appendIfMissing(records[hn], ip)
					rev = hn
				}
				if rev != "" {
					rev_ip, err := dns.ReverseAddr(ip.String())
					if err != nil {
						log.WithError(err).WithField("IP", ip.String()).Error("Error reversing ip for reverse dns")
					}
					rev_records[rev_ip] = rev
				}
			}
		}
	}
	//log.WithField("Records", records).Debug("Records updated")
	//log.WithField("Reverse", rev_records).Debug("Records updated")
}

var (
	leftNotaz09  *regexp.Regexp
	onlyaz09Dash *regexp.Regexp
)

func fullyQualify(n string) string {
	n = normalizeName(n)
	n = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(n, "."), strings.TrimSuffix(dom, ".")), ".")
	n = n + "." + dom
	return n
}

func normalizeName(n string) string {
	if leftNotaz09 == nil {
		leftNotaz09 = regexp.MustCompile(`^[^a-z0-9]+`)
	}
	if onlyaz09Dash == nil {
		onlyaz09Dash = regexp.MustCompile(`[^a-z0-9\-\.]+`)
	}
	n = strings.ToLower(n)
	n = string(leftNotaz09.ReplaceAllLiteral([]byte(n), []byte{}))
	n = string(onlyaz09Dash.ReplaceAllLiteral([]byte(n), []byte{}))
	return n
}

func handle(w dns.ResponseWriter, r *dns.Msg) {
	//log.WithField("Message", r).Debug("Handling DNS Request")
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = compress

	recordLock.RLock()
	defer recordLock.RUnlock()
	for _, q := range r.Question {
		if q.Qtype == dns.TypePTR {
			if rev, ok := rev_records[q.Name]; ok {
				//log.Debug("Reverse DNS Response")
				rr := &dns.PTR{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypePTR,
						Class:  dns.ClassINET,
						Ttl:    ttl,
					},
					Ptr: rev,
				}
				m.Answer = append(m.Answer, rr)
			}
			continue
		}
		if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
			continue
		}
		for _, ip := range records[strings.ToLower(q.Name)] {
			//log.WithField("IP", ip).Debug("Preparing response")
			if ip.To4() == nil {
				//log.Debug("IPv6 Response")
				rr := &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    ttl,
					},
					AAAA: ip,
				}
				if q.Qtype == dns.TypeAAAA {
					m.Answer = append(m.Answer, rr)
				} else {
					m.Extra = append(m.Extra, rr)
				}
				continue
			}
			//log.Debug("IPv4 Response")
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    ttl,
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

	//log.WithField("Response", m).Debug("Sending DNS Response")
	err := w.WriteMsg(m)
	if err != nil {
		log.WithError(err).Error("Failed to write DNS message")
	}
}

func serve(proto, listen string) {
	server := &dns.Server{Addr: listen, Net: proto, TsigSecret: nil}
	if err := server.ListenAndServe(); err != nil {
		log.WithError(err).Error("Failed to serve DNS")
	}
}
