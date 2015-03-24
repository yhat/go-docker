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

// NewDefaultDockerClient provides an arch specific default docker client.
// On linux it connects to the default docker socket, on OS X it looks for
// boot2docker environment variables.
func NewDefaultClient(timeout time.Duration) (*Client, error) {
	dockerHost := os.Getenv("DOCKER_HOST")
	if dockerHost == "" {
		return nil, fmt.Errorf("DOCKER_HOST environment not set")
	}
	dockerCerts := os.Getenv("DOCKER_CERT_PATH")
	if dockerCerts == "" {
		return NewClient(dockerHost, nil, timeout)
	}
	keyFile := filepath.Join(dockerCerts, "key.pem")
	certFile := filepath.Join(dockerCerts, "cert.pem")
	caFile := filepath.Join(dockerCerts, "ca.pem")
	caBytes, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("could not read certificate authority pem: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("could not add ca.pem to certificate pool")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("could not load key pairs: %v", err)
	}
	return NewClient(dockerHost, &tls.Config{
		Certificates:       []tls.Certificate{cert},
		ClientCAs:          pool,
		InsecureSkipVerify: true,
	}, timeout)
}
