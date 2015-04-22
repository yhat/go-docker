# Golang Docker client

[![GoDoc](http://godoc.org/github.com/yhat/go-docker?status.png)](http://godoc.org/github.com/yhat/go-docker)

This is a fork of the samalba/dockerclient library. It adds missing API calls
such as wait, commit, and attach as well as a splitter for Docker stream events
(like containers stdout and stderr). The fork also removes event callbacks and
tests against a Docker installation rather than mocks.

Example:

```go
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/yhat/go-docker"
)

func SayHi() error {
	timeout := 3 * time.Second

	cli, err := docker.NewDefaultClient(timeout)
	if err != nil {
		return err
	}

	// create a container
	config := &docker.ContainerConfig{
		Image: "ubuntu:14.04",
		Cmd:   []string{"echo", "hello from docker land"},
	}
	cid, err := cli.CreateContainer(config, "myimage")
	if err != nil {
		return err
	}

	// always remember to clean up after yourself
	defer cli.RemoveContainer(cid, true, false)

	// attach to the container
	streamOpts := &docker.AttachOptions{Stream: true, Stdout: true, Stderr: true}
	stream, err := cli.Attach(cid, streamOpts)
	if err != nil {
		return err
	}
	defer stream.Close()

	// concurrently write stream to stdout and stderr
	go docker.SplitStream(stream, os.Stdout, os.Stderr)

	// start the container
	err = cli.StartContainer(cid, &docker.HostConfig{})
	if err != nil {
		return err
	}

	// wait for the container to exit
	statusCode, err := cli.Wait(cid)
	if err != nil {
		return err
	}
	if statusCode != 0 {
		return fmt.Errorf("process returned bad status code: %d", statusCode)
	}

	return nil
}

func main() {
	if err := SayHi(); err != nil {
		panic(err)
	}
}
```
