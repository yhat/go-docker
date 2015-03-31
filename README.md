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
	"log"
	"os"
	"time"

	"github.com/yhat/go-docker"
)

func SayHi() error {
	cli, err := docker.NewClient("unix:///var/run/docker.sock", nil, 3*time.Second)
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
	defer func() {
		if err := cli.RemoveContainer(cid, true, false); err != nil {
			fmt.Printf("could not remove container: %v\n", err)
		}
	}()

	// attach to the container
	streamOpts := &docker.AttachOptions{Stream: true, Stdout: true, Stderr: true}
	stream, err := cli.Attach(cid, streamOpts)
	if err != nil {
		return err
		log.Fatalf("could not attach to container: %v", err)
	}
	defer stream.Close()

	// concurrently write stream to stdout and stderr
	go func() {
		if err := docker.SplitStream(stream, os.Stdout, os.Stderr); err != nil {
			fmt.Printf("error spliting stream: %v\n", err)
		}
	}()

	// start the container
	if err := cli.StartContainer(cid, &docker.HostConfig{}); err != nil {
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
