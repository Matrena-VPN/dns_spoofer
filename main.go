package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"DnsSpoofer/internal/dns"
	"DnsSpoofer/internal/proxy"
	"DnsSpoofer/internal/status"
	"DnsSpoofer/internal/udpsink"
)

// Default configuration values
var (
	defaultSpoofSuffixes = []string{
		// OpenAI / ChatGPT
		".openai.com",
		".chatgpt.com",
		".oaistatic.com",
		".oaiusercontent.com",
		// Google Gemini
		".gemini.google.com",
		".aistudio.google.com",
		".ai.google.dev",
		".generativelanguage.googleapis.com",
		".makersuite.google.com",
		// Cursor IDE
		".cursor.sh",
		".cursor.com",
		".cursorapi.com",
		".cursor-cdn.com",
		// Microsoft Copilot
		".copilot.microsoft.com",
		".bing.com",
		".bingapis.com",
		".edgeservices.bing.com",
		".edgecopilot.microsoft.com",
		// GitHub Copilot (only Copilot-specific domains, not general GitHub)
		".githubcopilot.com",
		".individual.githubcopilot.com",
		".api.individual.githubcopilot.com",
		".business.githubcopilot.com",
		".enterprise.githubcopilot.com",
		".copilot-proxy.githubusercontent.com",
		".origin-tracker.githubusercontent.com",
		".copilot-telemetry.githubusercontent.com",
		// Anthropic Claude
		".anthropic.com",
		".claude.ai",
		".claude.com",
		".clau.de",
		".claudeusercontent.com",
		".claudemcpclient.com",
		// JetBrains
		".jetbrains.com",
		".jetbrains.ai",
		".jetbrains.dev",
		".jetbrains.net",
		".jetbrains.org",
		".jetbrains.ru",
		".jetbrains.space",
		".jetbrains.com.cn",
		".intellij.net",
		".myjetbrains.com",
		".jb.gg",
		".kotl.in",
		".kotlinlang.org",
		".talkingkotlin.com",
		".kotlinconf.com",
		// Figma
		".figma.com",
		".figma.net",
		".figma.site",
	}
	defaultUpstreamDNS = []string{"8.8.8.8:53", "1.1.1.1:53"}
)

func main() {
	// Parse command line flags
	// Default spoof IP from environment variable, or use default server IP
	defaultSpoofIP := os.Getenv("DNS_SPOOFER_IP")
	if defaultSpoofIP == "" {
		defaultSpoofIP = "95.164.123.192" // Default server IP (can be overridden via DNS_SPOOFER_IP env var or -spoof-ip flag)
	}
	spoofIP := flag.String("spoof-ip", defaultSpoofIP, "IP address to return for spoofed domains (default: 95.164.123.192, or set DNS_SPOOFER_IP env var)")
	dnsPort := flag.String("dns-port", ":53", "DNS server listen address")
	httpPort := flag.String("http-port", ":80", "HTTP proxy listen address")
	httpsPort := flag.String("https-port", ":443", "HTTPS proxy listen address")
	udpSinkPort := flag.String("udp-sink-port", ":443", "UDP sink listen address (drops QUIC/HTTP3 traffic to force TCP fallback)")
	spoofSuffixes := flag.String("spoof-suffixes", strings.Join(defaultSpoofSuffixes, ","), "Comma-separated list of domain suffixes to spoof")
	upstreamDNS := flag.String("upstream-dns", strings.Join(defaultUpstreamDNS, ","), "Comma-separated list of upstream DNS servers")
	resolverDNS := flag.String("resolver-dns", "8.8.8.8:53", "DNS server for proxy to resolve backend hosts (to avoid loops)")
	statusAddr := flag.String("status-addr", "127.0.0.1:9100", "Status API listen address")

	flag.Parse()

	// Parse spoof IP
	ip := net.ParseIP(*spoofIP)
	if ip == nil {
		log.Fatalf("Invalid spoof IP: %s", *spoofIP)
	}

	// Parse suffixes
	suffixes := strings.Split(*spoofSuffixes, ",")
	for i := range suffixes {
		suffixes[i] = strings.TrimSpace(suffixes[i])
	}

	// Parse upstream DNS
	upstreams := strings.Split(*upstreamDNS, ",")
	for i := range upstreams {
		upstreams[i] = strings.TrimSpace(upstreams[i])
	}

	log.Println("=== DNS Spoofer + Proxy ===")
	log.Printf("Spoof IP: %s", ip)
	log.Printf("Spoof suffixes: %v", suffixes)
	log.Printf("DNS listen: %s", *dnsPort)
	log.Printf("HTTP listen: %s", *httpPort)
	log.Printf("HTTPS listen: %s", *httpsPort)
	log.Printf("UDP sink listen: %s (QUIC/HTTP3 drop)", *udpSinkPort)
	log.Printf("Upstream DNS: %v", upstreams)
	log.Printf("Resolver DNS: %s", *resolverDNS)
	log.Println("===========================")

	// Create and start DNS server
	dnsServer := dns.New(dns.Config{
		ListenAddr:      *dnsPort,
		SpoofIP:         ip,
		SpoofSuffixes:   suffixes,
		UpstreamDNS:     upstreams,
		UpstreamTimeout: 5 * time.Second,
	})

	if err := dnsServer.Start(); err != nil {
		log.Fatalf("Failed to start DNS server: %v", err)
	}

	// Create and start proxy server
	proxyServer := proxy.New(proxy.Config{
		HTTPAddr:        *httpPort,
		HTTPSAddr:       *httpsPort,
		AllowedSuffixes: suffixes,
		ResolverDNS:     *resolverDNS,
		DialTimeout:     5 * time.Second,
		PeekTimeout:     5 * time.Second,
	})

	if err := proxyServer.Start(); err != nil {
		log.Fatalf("Failed to start proxy server: %v", err)
	}

	// Create and start UDP sink (drops QUIC/HTTP3 traffic to force TCP fallback)
	udpSink := udpsink.New(udpsink.Config{
		ListenAddr: *udpSinkPort,
	})

	if err := udpSink.Start(); err != nil {
		log.Fatalf("Failed to start UDP sink: %v", err)
	}

	// Create and start status API server
	statusServer := status.New(status.Config{
		ListenAddr: *statusAddr,
	}, dnsServer, proxyServer, udpSink)

	if err := statusServer.Start(); err != nil {
		log.Fatalf("Failed to start status server: %v", err)
	}

	log.Println("All servers started successfully")

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	log.Printf("Received signal %v, shutting down...", sig)

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Shutdown all servers
	var shutdownErr error
	if err := dnsServer.Shutdown(ctx); err != nil {
		log.Printf("DNS server shutdown error: %v", err)
		shutdownErr = err
	}
	if err := proxyServer.Shutdown(ctx); err != nil {
		log.Printf("Proxy server shutdown error: %v", err)
		shutdownErr = err
	}
	if err := udpSink.Shutdown(ctx); err != nil {
		log.Printf("UDP sink shutdown error: %v", err)
		shutdownErr = err
	}
	if err := statusServer.Shutdown(ctx); err != nil {
		log.Printf("Status server shutdown error: %v", err)
		shutdownErr = err
	}

	if shutdownErr != nil {
		log.Println("Shutdown completed with errors")
		os.Exit(1)
	}

	log.Println("Shutdown completed successfully")
}
