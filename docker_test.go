package docker

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

var TestClientTimeout = time.Second

func newClient(t *testing.T) *Client {
	t.Parallel()
	cli, err := NewDefaultClient(TestClientTimeout)
	if err != nil {
		t.Fatalf("could not create client: %v", err)
	}
	return cli
}

func randName(t *testing.T) string {
	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		t.Fatalf("could not read random bytes: %v", err)
	}
	return fmt.Sprintf("%x", randBytes)
}

func TestInfo(t *testing.T) {
	cli := newClient(t)
	_, err := cli.Info()
	if err != nil {
		t.Fatalf("could not get info: %v", err)
	}
}

func TestListContainers(t *testing.T) {
	cli := newClient(t)
	config := ContainerConfig{
		Cmd: []string{"echo", "hi"},
	}
	name := randName(t)
	cid, err := cli.CreateContainer(&config, name)
	if err != nil {
		t.Fatalf("could not create container: %v", err)
	}
	defer func(cid string) {
		if err := cli.RemoveContainer(cid, true, false); err != nil {
			t.Errorf("could not remove container: %v", err)
		}
	}(cid)

	containers, err := cli.ListContainers(true, false, "")
	if err != nil {
		t.Errorf("could not list containers: %v", err)
		return
	}
	found := func() bool {
		for _, container := range containers {
			if container.Id == cid {
				return true
			}
		}
		return false
	}()
	if !found {
		t.Errorf("container '%s' not listed", name)
	}
}

func TestInspectContainer(t *testing.T) {
	cli := newClient(t)
	_, err := cli.InspectContainer("idonotexist")
	switch err {
	case nil:
		t.Fatalf("was able to inspect a non existent container")
	case ErrNotFound:
	default:
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestCreateContainer(t *testing.T) {
	cli := newClient(t)
	name := randName(t)
	config := &ContainerConfig{Cmd: []string{"echo", "hi"}}
	cid, err := cli.CreateContainer(config, name)
	if err != nil {
		t.Fatalf("could not create container: %v", err)
	}
	if err := cli.RemoveContainer(cid, true, false); err != nil {
		t.Errorf("could not remove container: %v", err)
	}
}

func TestSplitStream(t *testing.T) {
	cli := newClient(t)
	name := randName(t)
	n := 10 << 10 // 10GiB
	randBytes := make([]byte, n)
	tempFile, err := ioutil.TempFile("", "go-docker")
	if err != nil {
		t.Fatalf("could not create temp file: %v", err)
	}
	p := tempFile.Name()
	defer os.Remove(p)
	if _, err := tempFile.Write(randBytes); err != nil {
		t.Errorf("error writing to temp file: %v", err)
		return
	}

	dest := "/tmp/foo.txt"
	hostConfig := HostConfig{Binds: []string{p + ":" + dest}}
	config := &ContainerConfig{
		Image:      "ubuntu:trusty",
		Cmd:        []string{"cat", dest},
		Volumes:    map[string]struct{}{dest: {}},
		HostConfig: hostConfig,
	}

	cid, err := cli.CreateContainer(config, name)
	if err != nil {
		t.Errorf("could not create container: %v", err)
		return
	}
	defer func() {
		if err := cli.RemoveContainer(cid, true, false); err != nil {
			t.Errorf("could not remove container: %v", err)
		}
	}()
	o := &AttachOptions{
		Stream: true,
		Stdout: true,
		Stderr: true,
	}
	stream, err := cli.Attach(cid, o)
	if err != nil {
		t.Errorf("could not attach to container: %v", err)
		return
	}
	stdout := bytes.NewBuffer([]byte{})
	stderr := bytes.NewBuffer([]byte{})
	streamErr := make(chan error, 1)
	go func() {
		streamErr <- SplitStream(stream, stdout, stderr)
	}()

	if err := cli.StartContainer(cid, &hostConfig); err != nil {
		t.Errorf("could not start container: %v", err)
		return
	}
	rc, err := cli.Wait(cid)
	if err != nil {
		t.Errorf("error waiting for container: %v", err)
		return
	}
	if rc != 0 {
		t.Errorf("non zero return code: %d", rc)
		return
	}
	if err := <-streamErr; err != nil {
		t.Errorf("could not split stream: %v", err)
		return
	}

	stdoutBytes := stdout.Bytes()
	stderrBytes := stderr.Bytes()
	if n := len(stderrBytes); n != 0 {
		t.Errorf("did not expect any bytes to stderr, got: %d", n)
	}

	if bytes.Compare(stdoutBytes, randBytes) != 0 {
		t.Errorf("stdout bytes were not identical to rand bytes")
	}
}

func TestCommit(t *testing.T) {
	cli := newClient(t)
	name1 := randName(t)
	name2 := randName(t)

	config := &ContainerConfig{
		Image: "ubuntu:trusty",
		Cmd:   []string{"touch", "/tmp/foo"},
	}

	cid, err := cli.CreateContainer(config, name1)
	if err != nil {
		t.Errorf("could not create container: %v", err)
		return
	}
	defer func(cid string) {
		if err := cli.RemoveContainer(cid, true, false); err != nil {
			t.Errorf("could not remove container: %v", err)
		}
	}(cid)
	startWait := func(cid string) error {
		if err := cli.StartContainer(cid, &HostConfig{}); err != nil {
			return fmt.Errorf("could not start container: %v", err)
		}
		rc, err := cli.Wait(cid)
		if err != nil {
			return fmt.Errorf("error waiting for container: %v", err)
		}
		if rc != 0 {
			return fmt.Errorf("non zero return code: %d", rc)
		}
		return nil
	}
	if err := startWait(cid); err != nil {
		t.Error(err)
		return
	}
	ops := &CommitOptions{
		Container: cid,
		Repo:      "go-docker",
		Tag:       "TestCommit",
	}
	id, err := cli.Commit(ops, config)
	if err != nil {
		t.Errorf("could not commit container: %v", err)
		return
	}

	defer func(id string) {
		if _, err := cli.RemoveImage(id); err != nil {
			t.Errorf("could not remove container: %v", err)
		}
	}(id)

	config2 := &ContainerConfig{
		Image: id,
		Cmd:   []string{"cat", "/tmp/foo"},
	}
	cid, err = cli.CreateContainer(config2, name2)
	if err != nil {
		t.Errorf("could not create container: %v", err)
		return
	}
	defer func(cid string) {
		if err := cli.RemoveContainer(cid, true, false); err != nil {
			t.Errorf("could not remove container: %v", err)
		}
	}(cid)

	if err := startWait(cid); err != nil {
		t.Error(err)
	}
}

func TestChanges(t *testing.T) {
	cli := newClient(t)
	name1 := randName(t)

	config := &ContainerConfig{
		Image: "ubuntu:trusty",
		Cmd: []string{
			"/bin/bash", "-c",
			"touch /tmp/foo && rm /etc/debian_version && touch /etc/passwd",
		},
	}

	cid, err := cli.CreateContainer(config, name1)
	if err != nil {
		t.Errorf("could not create container: %v", err)
		return
	}
	defer func(cid string) {
		if err := cli.RemoveContainer(cid, true, false); err != nil {
			t.Errorf("could not remove container: %v", err)
		}
	}(cid)
	startWait := func(cid string) error {
		if err := cli.StartContainer(cid, &HostConfig{}); err != nil {
			return fmt.Errorf("could not start container: %v", err)
		}
		rc, err := cli.Wait(cid)
		if err != nil {
			return fmt.Errorf("error waiting for container: %v", err)
		}
		if rc != 0 {
			return fmt.Errorf("non zero return code: %d", rc)
		}
		return nil
	}
	if err := startWait(cid); err != nil {
		t.Error(err)
		return
	}
	changes, err := cli.Changes(cid)
	if err != nil {
		t.Errorf("could not get changes for container: %v", err)
		return
	}

	// Make sure we we all the appropriate changes.
	if len(changes) != 5 {
		t.Errorf("5 changes expected, %d returned: %v", len(changes), changes)
	}

	// Deleted /etc/debian_version
	if changes[0].Kind != ChangeModify || changes[0].Path != "/etc" {
		t.Errorf("/etc not modified")
	}
	if changes[1].Kind != ChangeDelete || changes[1].Path != "/etc/debian_version" {
		t.Errorf("/etc/debian_version not deleted")
	}

	// Modified /etc/passwd
	if changes[2].Kind != ChangeModify || changes[2].Path != "/etc/passwd" {
		t.Errorf("/etc/passwd not modified")
	}

	// Created /tmp/foo
	if changes[3].Kind != ChangeModify || changes[3].Path != "/tmp" {
		t.Errorf("/tmp not modified")
	}
	if changes[4].Kind != ChangeAdd || changes[4].Path != "/tmp/foo" {
		t.Errorf("/tmp/foo not created")
	}
}
