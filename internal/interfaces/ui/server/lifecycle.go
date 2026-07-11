package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
)

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"BBPTS Ingest Authority"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	var cert tls.Certificate
	cert.Certificate = append(cert.Certificate, derBytes)
	cert.PrivateKey = priv

	return cert, nil
}

func Start(cfg Config, db *storage.DB, configPath string, masterDBPath string) error {
	if db == nil {
		return fmt.Errorf("database client is required")
	}

	if err := BootstrapAdminUser(db); err != nil {
		slog.Error("failed to bootstrap admin user", "error", err)
	}

	api := NewAPI(db, configPath, masterDBPath)

	mux := http.NewServeMux()

	RegisterRoutes(mux, api)

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Port)

	handler := securityHeadersMiddleware(authMiddleware(db, mux))

	if cfg.TLSEnabled {
		slog.Info("dashboard server starting with TLS", "addr", "https://"+addr)
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			server := &http.Server{
				Addr:              addr,
				Handler:           handler,
				ReadHeaderTimeout: 10 * time.Second,
			}
			return server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		}

		cert, err := generateSelfSignedCert()
		if err != nil {
			return fmt.Errorf("failed to generate self-signed cert: %w", err)
		}
		slog.Info("using generated self-signed certificate for HTTPS")
		fmt.Printf("\n")
		fmt.Printf("  BBPTS Dashboard is live (HTTPS)!\n")
		fmt.Printf("  \033[36mhttps://%s\033[0m\n", addr)
		fmt.Printf("\n")
		fmt.Printf("  Open the URL above in your browser.\n")
		fmt.Printf("  Press 'q' or Ctrl+C to stop.\n\n")
		server := &http.Server{
			Addr:    addr,
			Handler: handler,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
			ReadHeaderTimeout: 10 * time.Second,
		}
		return server.ListenAndServeTLS("", "")
	}

	slog.Info("dashboard server starting", "addr", "http://"+addr)
	fmt.Printf("\n")
	fmt.Printf("  BBPTS Dashboard is live!\n")
	fmt.Printf("  \033[36mhttp://%s\033[0m\n", addr)
	fmt.Printf("\n")
	fmt.Printf("  Open the URL above in your browser.\n")
	fmt.Printf("  Press 'q' or Ctrl+C to stop.\n\n")
	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return server.ListenAndServe()
}
