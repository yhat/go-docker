package docker

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

// NewDefaultClient provides an arch specific default docker client.
// On linux it connects to the default docker socket, on OS X it looks for
// boot2docker environment variables.
func NewDefaultClient(timeout time.Duration) (*Client, error) {
	host := os.Getenv("DOCKER_HOST")
	if host == "" {
		return nil, fmt.Errorf("DOCKER_HOST environment variable not set")
	}
	certPath := os.Getenv("DOCKER_CERT_PATH")
	if certPath == "" {
		return NewClient(host, nil, timeout)
	}

	tlsConfig := tls.Config{}
	tlsConfig.InsecureSkipVerify = true

	tlsVerify := os.Getenv("DOCKER_TLS_VERIFY")
	if tlsVerify == "1" {
		certPool := x509.NewCertPool()
		ca := filepath.Join(certPath, "ca.pem")
		file, err := ioutil.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("Couldn't read ca cert %s: %s", ca, err)
		}
		certPool.AppendCertsFromPEM(file)
		tlsConfig.RootCAs = certPool
		tlsConfig.InsecureSkipVerify = false
		certFile := filepath.Join(certPath, "cert.pem")
		keyFile := filepath.Join(certPath, "key.pem")

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("Couldn't load X509 key pair: %v", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		// Avoid fallback to SSL protocols < TLS1.0
		tlsConfig.MinVersion = tls.VersionTLS10
	}

	return NewClient(host, &tlsConfig, timeout)
}
