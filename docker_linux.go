package docker

import "time"

// NewDefaultClient provides an arch specific default docker client.
// On linux it connects to the default docker socket, on OS X it looks for
// boot2docker environment variables.
func NewDefaultClient(timeout time.Duration) (*Client, error) {
	dockerHost := "unix:///var/run/docker.sock"
	return NewClient(dockerHost, nil, timeout)
}
