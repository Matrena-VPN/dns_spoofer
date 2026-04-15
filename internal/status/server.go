package status

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	dnsserver "DnsSpoofer/internal/dns"
	"DnsSpoofer/internal/proxy"
	"DnsSpoofer/internal/udpsink"
)

type Config struct {
	ListenAddr string
}

type Server struct {
	config     Config
	httpServer *http.Server
	dns        *dnsserver.Server
	proxy      *proxy.Server
	sink       *udpsink.Sink
}

type statusResponse struct {
	Status string `json:"status"`
	Uptime string `json:"uptime"`
	DNS    struct {
		QueriesTotal     uint64   `json:"queries_total"`
		QueriesSpoofed   uint64   `json:"queries_spoofed"`
		QueriesForwarded uint64   `json:"queries_forwarded"`
		SpoofIP          string   `json:"spoof_ip"`
		SpoofSuffixes    []string `json:"spoof_suffixes"`
	} `json:"dns"`
	Proxy struct {
		TunnelsTotal  uint64 `json:"tunnels_total"`
		TunnelsActive int64  `json:"tunnels_active"`
	} `json:"proxy"`
	UDPSink struct {
		PacketsDropped uint64 `json:"packets_dropped"`
		ICMPSent       uint64 `json:"icmp_sent"`
	} `json:"udp_sink"`
}

func New(cfg Config, dns *dnsserver.Server, proxy *proxy.Server, sink *udpsink.Sink) *Server {
	return &Server{
		config: cfg,
		dns:    dns,
		proxy:  proxy,
		sink:   sink,
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	dnsStats := s.dns.Stats()
	proxyStats := s.proxy.Stats()

	resp := statusResponse{
		Status: "running",
		Uptime: dnsStats.Uptime.Truncate(time.Second).String(),
	}
	resp.DNS.QueriesTotal = dnsStats.QueriesTotal
	resp.DNS.QueriesSpoofed = dnsStats.QueriesSpoofed
	resp.DNS.QueriesForwarded = dnsStats.QueriesForwarded
	resp.DNS.SpoofIP = dnsStats.SpoofIP
	resp.DNS.SpoofSuffixes = dnsStats.SpoofSuffixes
	resp.Proxy.TunnelsTotal = proxyStats.TunnelsTotal
	resp.Proxy.TunnelsActive = proxyStats.TunnelsActive
	resp.UDPSink.PacketsDropped = s.sink.DroppedCount()
	resp.UDPSink.ICMPSent = s.sink.ICMPCount()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(resp)
}

// handleCheck returns the client's IP so the frontend can compare it against SpoofIP.
func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	ip := r.Header.Get("X-Real-IP")
	if ip == "" {
		ip = r.Header.Get("X-Forwarded-For")
		if idx := strings.Index(ip, ","); idx != -1 {
			ip = strings.TrimSpace(ip[:idx])
		}
	}
	if ip == "" {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		ip = host
	}

	spoofIP := s.dns.Stats().SpoofIP

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"client_ip":  ip,
		"spoof_ip":   spoofIP,
		"using_spoof": ip == spoofIP,
	})
}

// handleDoH implements RFC 8484 DNS over HTTPS.
// GET  /dns-query?dns=<base64url>  (wire format)
// POST /dns-query  Content-Type: application/dns-message  (wire format body)
func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	var reqBytes []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		param := r.URL.Query().Get("dns")
		if param == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		reqBytes, err = base64.RawURLEncoding.DecodeString(param)
		if err != nil {
			http.Error(w, "invalid base64url", http.StatusBadRequest)
			return
		}

	case http.MethodPost:
		ct := r.Header.Get("Content-Type")
		if ct != "application/dns-message" {
			http.Error(w, "unsupported content-type", http.StatusUnsupportedMediaType)
			return
		}
		reqBytes, err = io.ReadAll(io.LimitReader(r.Body, 65535))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	respBytes, err := s.dns.HandleMessage(reqBytes)
	if err != nil {
		log.Printf("[DoH] Error processing query: %v", err)
		http.Error(w, "dns processing error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "max-age=60")
	w.Write(respBytes)
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/check", s.handleCheck)
	mux.HandleFunc("/dns-query", s.handleDoH)

	s.httpServer = &http.Server{
		Addr:    s.config.ListenAddr,
		Handler: mux,
	}

	go func() {
		log.Printf("[Status] API server started on %s", s.config.ListenAddr)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[Status] Server error: %v", err)
		}
	}()

	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}
