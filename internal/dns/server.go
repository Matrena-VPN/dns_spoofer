package dns

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Config holds DNS server configuration
type Config struct {
	ListenAddr      string        // Address to listen on (e.g., ":53")
	SpoofIP         net.IP        // IP to return for spoofed domains
	SpoofSuffixes   []string      // Domain suffixes to spoof (e.g., ".openai.com")
	UpstreamDNS     []string      // Upstream DNS servers (e.g., ["8.8.8.8:53", "1.1.1.1:53"])
	UpstreamTimeout time.Duration // Timeout for upstream queries
}

// Server is a DNS server that spoofs specific domains
type Server struct {
	config     Config
	udpServer  *dns.Server
	tcpServer  *dns.Server
	client     *dns.Client
	tcpClient  *dns.Client
	shutdownCh chan struct{}
	wg         sync.WaitGroup
	startTime  time.Time

	queriesTotal    atomic.Uint64
	queriesSpoofed  atomic.Uint64
	queriesForwarded atomic.Uint64
}

// New creates a new DNS server
func New(cfg Config) *Server {
	// Normalize suffixes to lowercase
	suffixes := make([]string, len(cfg.SpoofSuffixes))
	for i, s := range cfg.SpoofSuffixes {
		suffixes[i] = strings.ToLower(s)
	}
	cfg.SpoofSuffixes = suffixes

	if cfg.UpstreamTimeout == 0 {
		cfg.UpstreamTimeout = 5 * time.Second
	}

	return &Server{
		config:     cfg,
		client:     &dns.Client{Timeout: cfg.UpstreamTimeout},
		tcpClient:  &dns.Client{Net: "tcp", Timeout: cfg.UpstreamTimeout},
		shutdownCh: make(chan struct{}),
		startTime:  time.Now(),
	}
}

// shouldSpoof checks if the domain should be spoofed
func (s *Server) shouldSpoof(name string) bool {
	// Normalize: lowercase and remove trailing dot
	name = strings.ToLower(strings.TrimSuffix(name, "."))

	for _, suffix := range s.config.SpoofSuffixes {
		// Remove leading dot from suffix for comparison
		cleanSuffix := strings.TrimPrefix(suffix, ".")

		// Match exact domain or subdomain
		if name == cleanSuffix || strings.HasSuffix(name, "."+cleanSuffix) {
			return true
		}
	}
	return false
}

// syntheticSOA returns a minimal SOA record for NODATA responses.
// The SOA TTL controls how long resolvers cache the negative answer.
func syntheticSOA(qname string, ttl uint32) dns.RR {
	zone := qname
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ns:      "ns.spoofed.",
		Mbox:    "hostmaster.spoofed.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  ttl,
	}
}

// handleRequest handles incoming DNS requests
func (s *Server) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = false

	for _, q := range r.Question {
		s.queriesTotal.Add(1)
		log.Printf("[DNS] Query: %s (type %s)", q.Name, dns.TypeToString[q.Qtype])

		if s.shouldSpoof(q.Name) {
			s.queriesSpoofed.Add(1)
			switch q.Qtype {
			case dns.TypeA:
				log.Printf("[DNS] Spoofing %s -> %s", q.Name, s.config.SpoofIP)
				rr := &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					A: s.config.SpoofIP.To4(),
				}
				m.Answer = append(m.Answer, rr)

			case dns.TypeAAAA:
				if ip6 := s.config.SpoofIP.To16(); ip6 != nil && s.config.SpoofIP.To4() == nil {
					rr := &dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
							Ttl:    60,
						},
						AAAA: ip6,
					}
					m.Answer = append(m.Answer, rr)
				} else {
					m.Ns = append(m.Ns, syntheticSOA(q.Name, 60))
				}
				log.Printf("[DNS] Spoofing AAAA %s -> (empty, forcing IPv4)", q.Name)

			case dns.TypeHTTPS, dns.TypeSVCB:
				log.Printf("[DNS] Blocking %s %s -> NODATA (preventing QUIC/ECH)", dns.TypeToString[q.Qtype], q.Name)
				m.Ns = append(m.Ns, syntheticSOA(q.Name, 60))

			default:
				s.forwardToUpstream(w, r)
				return
			}
		} else {
			s.forwardToUpstream(w, r)
			return
		}
	}

	// Reflect EDNS0 OPT from request so clients don't downgrade
	if opt := r.IsEdns0(); opt != nil {
		edns := &dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeOPT,
			},
		}
		edns.SetVersion(0)
		edns.SetUDPSize(1232)
		if opt.Do() {
			edns.SetDo()
		}
		m.Extra = append(m.Extra, edns)
	}

	if err := w.WriteMsg(m); err != nil {
		log.Printf("[DNS] Error writing response: %v", err)
	}
}

// forwardToUpstream forwards the request to upstream DNS servers.
// When the upstream returns a truncated (TC=1) UDP response, the
// exchange is automatically retried over TCP so the client gets
// the full answer without needing its own TCP retry.
func (s *Server) forwardToUpstream(w dns.ResponseWriter, r *dns.Msg) {
	s.queriesForwarded.Add(1)
	var lastErr error

	for _, upstream := range s.config.UpstreamDNS {
		log.Printf("[DNS] Forwarding to upstream %s", upstream)

		resp, _, err := s.client.Exchange(r, upstream)
		if err != nil {
			log.Printf("[DNS] Upstream %s error: %v", upstream, err)
			lastErr = err
			continue
		}

		if resp.Truncated {
			log.Printf("[DNS] Upstream %s returned truncated response, retrying over TCP", upstream)
			tcpResp, _, tcpErr := s.tcpClient.Exchange(r, upstream)
			if tcpErr != nil {
				log.Printf("[DNS] Upstream %s TCP retry error: %v", upstream, tcpErr)
			} else {
				resp = tcpResp
			}
		}

		if err := w.WriteMsg(resp); err != nil {
			log.Printf("[DNS] Error writing upstream response: %v", err)
		}
		return
	}

	// All upstreams failed
	log.Printf("[DNS] All upstreams failed, last error: %v", lastErr)
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeServerFailure)
	if err := w.WriteMsg(m); err != nil {
		log.Printf("[DNS] Error writing SERVFAIL: %v", err)
	}
}

// Start starts the DNS server (UDP + TCP)
func (s *Server) Start() error {
	handler := dns.HandlerFunc(s.handleRequest)

	s.udpServer = &dns.Server{
		Addr:    s.config.ListenAddr,
		Net:     "udp",
		Handler: handler,
	}

	s.tcpServer = &dns.Server{
		Addr:    s.config.ListenAddr,
		Net:     "tcp",
		Handler: handler,
	}

	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		log.Printf("[DNS] Starting UDP server on %s", s.config.ListenAddr)
		if err := s.udpServer.ListenAndServe(); err != nil {
			select {
			case <-s.shutdownCh:
			default:
				log.Printf("[DNS] UDP server error: %v", err)
			}
		}
	}()
	go func() {
		defer s.wg.Done()
		log.Printf("[DNS] Starting TCP server on %s", s.config.ListenAddr)
		if err := s.tcpServer.ListenAndServe(); err != nil {
			select {
			case <-s.shutdownCh:
			default:
				log.Printf("[DNS] TCP server error: %v", err)
			}
		}
	}()

	return nil
}

// HandleMessage processes a raw DNS wire-format message and returns the response.
// Used by the DoH handler to reuse the same spoofing/forwarding logic.
func (s *Server) HandleMessage(req []byte) ([]byte, error) {
	r := new(dns.Msg)
	if err := r.Unpack(req); err != nil {
		return nil, fmt.Errorf("unpack DNS message: %w", err)
	}

	w := &bufferResponseWriter{}
	s.handleRequest(w, r)
	if w.msg == nil {
		return nil, fmt.Errorf("no response generated")
	}
	return w.msg.Pack()
}

type bufferResponseWriter struct {
	msg *dns.Msg
}

func (w *bufferResponseWriter) LocalAddr() net.Addr                  { return nil }
func (w *bufferResponseWriter) RemoteAddr() net.Addr                 { return nil }
func (w *bufferResponseWriter) WriteMsg(m *dns.Msg) error            { w.msg = m; return nil }
func (w *bufferResponseWriter) Write([]byte) (int, error)            { return 0, nil }
func (w *bufferResponseWriter) Close() error                         { return nil }
func (w *bufferResponseWriter) TsigStatus() error                    { return nil }
func (w *bufferResponseWriter) TsigTimersOnly(bool)                  {}
func (w *bufferResponseWriter) Hijack()                              {}

// Stats returns current server statistics
type Stats struct {
	Uptime          time.Duration
	QueriesTotal    uint64
	QueriesSpoofed  uint64
	QueriesForwarded uint64
	SpoofIP         string
	SpoofSuffixes   []string
}

func (s *Server) Stats() Stats {
	return Stats{
		Uptime:           time.Since(s.startTime),
		QueriesTotal:     s.queriesTotal.Load(),
		QueriesSpoofed:   s.queriesSpoofed.Load(),
		QueriesForwarded: s.queriesForwarded.Load(),
		SpoofIP:          s.config.SpoofIP.String(),
		SpoofSuffixes:    s.config.SpoofSuffixes,
	}
}

// Shutdown gracefully shuts down the DNS server
func (s *Server) Shutdown(ctx context.Context) error {
	close(s.shutdownCh)

	var firstErr error
	if s.udpServer != nil {
		if err := s.udpServer.ShutdownContext(ctx); err != nil {
			firstErr = fmt.Errorf("DNS UDP shutdown: %w", err)
		}
	}
	if s.tcpServer != nil {
		if err := s.tcpServer.ShutdownContext(ctx); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("DNS TCP shutdown: %w", err)
		}
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return firstErr
	case <-ctx.Done():
		return ctx.Err()
	}
}
