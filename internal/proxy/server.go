package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config holds proxy server configuration
type Config struct {
	HTTPAddr        string        // Address for HTTP proxy (e.g., ":80")
	HTTPSAddr       string        // Address for HTTPS proxy (e.g., ":443")
	AllowedSuffixes []string      // Domain suffixes allowed for proxying
	ResolverDNS     string        // DNS server for resolving backend hosts (e.g., "8.8.8.8:53")
	DialTimeout     time.Duration // Timeout for connecting to backend
	PeekTimeout     time.Duration // Timeout for reading initial bytes (SNI/Host)
}

// Server is a TCP proxy that routes based on SNI/Host header
type Server struct {
	config        Config
	httpListener  net.Listener
	httpsListener net.Listener
	resolver      *net.Resolver
	shutdownCh    chan struct{}
	wg            sync.WaitGroup

	tunnelsTotal  atomic.Uint64
	tunnelsActive atomic.Int64
}

// New creates a new proxy server
func New(cfg Config) *Server {
	// Normalize suffixes
	suffixes := make([]string, len(cfg.AllowedSuffixes))
	for i, s := range cfg.AllowedSuffixes {
		suffixes[i] = strings.ToLower(s)
	}
	cfg.AllowedSuffixes = suffixes

	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 5 * time.Second
	}
	if cfg.PeekTimeout == 0 {
		cfg.PeekTimeout = 5 * time.Second
	}

	return &Server{
		config:     cfg,
		resolver:   NewResolver(cfg.ResolverDNS, cfg.DialTimeout),
		shutdownCh: make(chan struct{}),
	}
}

// isAllowed checks if the host is in the allowed suffixes list
func (s *Server) isAllowed(host string) bool {
	host = strings.ToLower(host)

	for _, suffix := range s.config.AllowedSuffixes {
		cleanSuffix := strings.TrimPrefix(suffix, ".")
		if host == cleanSuffix || strings.HasSuffix(host, "."+cleanSuffix) {
			return true
		}
	}
	return false
}

// Start starts both HTTP and HTTPS proxy listeners
func (s *Server) Start() error {
	var err error

	// Start HTTP listener
	if s.config.HTTPAddr != "" {
		s.httpListener, err = net.Listen("tcp", s.config.HTTPAddr)
		if err != nil {
			return fmt.Errorf("HTTP listener: %w", err)
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.acceptLoop(s.httpListener, false)
		}()
		log.Printf("[Proxy] HTTP listener started on %s", s.config.HTTPAddr)
	}

	// Start HTTPS listener
	if s.config.HTTPSAddr != "" {
		s.httpsListener, err = net.Listen("tcp", s.config.HTTPSAddr)
		if err != nil {
			if s.httpListener != nil {
				s.httpListener.Close()
			}
			return fmt.Errorf("HTTPS listener: %w", err)
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.acceptLoop(s.httpsListener, true)
		}()
		log.Printf("[Proxy] HTTPS listener started on %s", s.config.HTTPSAddr)
	}

	return nil
}

// acceptLoop accepts connections and handles them
func (s *Server) acceptLoop(listener net.Listener, isTLS bool) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.shutdownCh:
				return
			default:
				log.Printf("[Proxy] Accept error: %v", err)
				continue
			}
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(conn, isTLS)
		}()
	}
}

// handleConnection handles a single client connection
func (s *Server) handleConnection(clientConn net.Conn, isTLS bool) {
	defer clientConn.Close()

	// Set deadline for peeking
	if err := clientConn.SetReadDeadline(time.Now().Add(s.config.PeekTimeout)); err != nil {
		log.Printf("[Proxy] SetReadDeadline error: %v", err)
		return
	}

	var host string
	var clientReader io.Reader
	var port string
	var err error

	if isTLS {
		port = "443"
		// Extract SNI from TLS ClientHello
		hello, reader, peekErr := PeekClientHello(clientConn)
		if peekErr != nil {
			log.Printf("[Proxy] SNI peek error: %v", peekErr)
			return
		}
		host = hello.ServerName
		clientReader = reader
		log.Printf("[Proxy] TLS connection, SNI: %s", host)
	} else {
		port = "80"
		// Extract Host from HTTP headers
		httpHost, reader, peekErr := PeekHTTPHost(clientConn)
		if peekErr != nil {
			log.Printf("[Proxy] HTTP Host peek error: %v", peekErr)
			return
		}
		host = httpHost
		clientReader = reader
		log.Printf("[Proxy] HTTP connection, Host: %s", host)
	}

	// Clear the read deadline
	if err = clientConn.SetReadDeadline(time.Time{}); err != nil {
		log.Printf("[Proxy] Clear deadline error: %v", err)
		return
	}

	// Check if host is allowed
	if !s.isAllowed(host) {
		log.Printf("[Proxy] Host not allowed: %s", host)
		return
	}

	// Resolve host to IP using our custom resolver (to avoid loops)
	ctx, cancel := context.WithTimeout(context.Background(), s.config.DialTimeout)
	defer cancel()

	ip, err := ResolveHost(ctx, s.resolver, host)
	if err != nil {
		log.Printf("[Proxy] Resolve error for %s: %v", host, err)
		return
	}

	// Connect to backend
	backendAddr := net.JoinHostPort(ip, port)
	log.Printf("[Proxy] Connecting to backend %s (%s)", backendAddr, host)

	backendConn, err := net.DialTimeout("tcp", backendAddr, s.config.DialTimeout)
	if err != nil {
		log.Printf("[Proxy] Backend dial error: %v", err)
		return
	}
	defer backendConn.Close()

	s.tunnelsTotal.Add(1)
	s.tunnelsActive.Add(1)
	defer s.tunnelsActive.Add(-1)

	log.Printf("[Proxy] Tunnel established: %s <-> %s (%s)", clientConn.RemoteAddr(), backendAddr, host)

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Backend
	go func() {
		defer wg.Done()
		_, err := io.Copy(backendConn, clientReader)
		if err != nil && !isClosedError(err) {
			log.Printf("[Proxy] Client->Backend copy error: %v", err)
		}
		// Signal EOF to backend
		if tcpConn, ok := backendConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	// Backend -> Client
	go func() {
		defer wg.Done()
		_, err := io.Copy(clientConn, backendConn)
		if err != nil && !isClosedError(err) {
			log.Printf("[Proxy] Backend->Client copy error: %v", err)
		}
		// Signal EOF to client
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
	log.Printf("[Proxy] Tunnel closed: %s <-> %s", clientConn.RemoteAddr(), backendAddr)
}

// isClosedError checks if the error is due to a closed connection
func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "broken pipe")
}

// Stats returns proxy statistics
type Stats struct {
	TunnelsTotal  uint64
	TunnelsActive int64
}

func (s *Server) Stats() Stats {
	return Stats{
		TunnelsTotal:  s.tunnelsTotal.Load(),
		TunnelsActive: s.tunnelsActive.Load(),
	}
}

// Shutdown gracefully shuts down the proxy server
func (s *Server) Shutdown(ctx context.Context) error {
	close(s.shutdownCh)

	if s.httpListener != nil {
		s.httpListener.Close()
	}
	if s.httpsListener != nil {
		s.httpsListener.Close()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
