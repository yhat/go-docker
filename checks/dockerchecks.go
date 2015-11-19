package checks

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yhat/go-docker"
)

var dockerSock = "unix:///var/run/docker.sock"

type Check func() error

type namedCheck struct {
	Name  string
	Check Check
}

type Checker struct {
	checks []namedCheck
}

func (c *Checker) Register(check Check, name string) {
	c.checks = append(c.checks, namedCheck{
		Name:  name,
		Check: check,
	})
}

func (c *Checker) Run() (exitCode int) {
	maxNameLen := 0
	for _, check := range c.checks {
		if n := len(check.Name); maxNameLen < n {
			maxNameLen = n
		}
	}
	s := strconv.Itoa(maxNameLen)
	pad := func(name string) string {
		return fmt.Sprintf("%-"+s+"s", name)
	}
	var err error
	for _, check := range c.checks {
		name := pad(check.Name)
		fmt.Print(name + " ... ")
		start := time.Now()
		err = check.Check()
		delta := time.Now().Sub(start)
		if err != nil {
			exitCode = 2
			fmt.Println("ERROR")
			fmt.Printf("\t%v\n", err)
		} else {
			fmt.Printf("OK (%s)\n", delta)
		}
	}
	return 0
}

func newClient() (*docker.Client, error) {
	return docker.NewClient(dockerSock, nil, 3*time.Second)
}

// CheckDockerSocket confirms that docker can be reached
func CheckDockerSocket() error {
	cli, err := newClient()
	if err != nil {
		return fmt.Errorf("creating client: %v", err)
	}
	_, err = cli.Info()
	if err != nil {
		return fmt.Errorf("simple ping: %v", err)
	}
	return nil
}

// CheckVersion confirms docker is at least the version passed.
func CheckVersion(minVersion []int) Check {
	return func() error {
		cli, err := newClient()
		if err != nil {
			return fmt.Errorf("creating client: %v", err)
		}
		v, err := cli.Version()
		if err != nil {
			return fmt.Errorf("getting version: %v", err)
		}
		return versionAtLeast(v.Version, minVersion)
	}
}

func versionAtLeast(vStr string, minVersion []int) error {
	vParts := strings.Split(vStr, ".")
	n := len(vParts)
	if n == 0 {
		return fmt.Errorf("parsing version '%s'", vStr)
	}

	var err error
	version := make([]int, len(vParts))
	for i, p := range vParts {
		version[i], err = strconv.Atoi(p)
		if err != nil {
			return fmt.Errorf("parsing version '%s' %v", vStr, err)
		}
	}

	if n > len(minVersion) {
		version = version[:len(minVersion)]
	}
	for i, vp := range version {
		minVP := minVersion[i]
		if minVP > vp {
			return fmt.Errorf("'%s' is not at least '%d'", vStr, minVersion)
		} else if minVP < vp {
			return nil
		}
	}
	if n < len(minVersion) {
		return fmt.Errorf("'%s' is not at least '%d'", vStr, minVersion)
	}
	return nil
}

// CheckDriver confirms that docker is using the provided driver.
func CheckDriver(driver string) Check {
	return func() error {
		cli, err := newClient()
		if err != nil {
			return fmt.Errorf("creating client: %v", err)
		}
		info, err := cli.Info()
		if err != nil {
			return fmt.Errorf("getting info: %v", err)
		}
		if info.Driver != driver {
			return fmt.Errorf("driver is '%s' not 'driver'", info.Driver, driver)
		}
		return nil
	}
}

// CheckSimpleCommand executes a simple echo command to ensure docker can
// create and run a container.
func CheckSimpleCommand() (err error) {
	cli, err := newClient()
	if err != nil {
		return fmt.Errorf("creating client: %v", err)
	}
	echoStr := "hello"
	config := &docker.ContainerConfig{
		Image: "ubuntu:14.04",
		Cmd:   []string{"echo", "-n", echoStr},
	}
	cid, err := cli.CreateContainer(config, "hellotest")
	if err != nil {
		return fmt.Errorf("creating container: %v", err)
	}
	defer func() {
		rcErr := cli.RemoveContainer(cid, true, false)
		if err == nil {
			err = rcErr
		} else if rcErr != nil {
			fmt.Fprintf(os.Stderr, "removing container %v\n", rcErr)
		}
	}()

	// attach to the container
	streamOpts := &docker.AttachOptions{Stream: true, Stdout: true, Stderr: true}
	stream, err := cli.Attach(cid, streamOpts)
	if err != nil {
		return err
	}
	defer stream.Close()

	// start the container
	err = cli.StartContainer(cid, &docker.HostConfig{})
	if err != nil {
		return err
	}

	var stderr bytes.Buffer
	var stdout bytes.Buffer
	if err = docker.SplitStream(stream, &stdout, &stderr); err != nil {
		return fmt.Errorf("reading stdout: %v", err)
	}

	// wait for the container to exit
	exitCode, err := cli.Wait(cid)
	if err != nil {
		return err
	}

	if exitCode != 0 {
		return fmt.Errorf("bad exit code %d %s", exitCode, stderr)
	}
	if out := stdout.String(); out != echoStr {
		return fmt.Errorf("expected '%s' from echo, got '%s'", echoStr, out)
	}
	if sErr := stderr.String(); sErr != "" {
		return fmt.Errorf("expected no response from stderr, got '%s'", sErr)
	}

	return nil
}

// CheckExposedPort confirms that docker can expose a port to the host machine
// when creating a container.
func CheckExposedPort() (err error) {
	cli, err := newClient()
	if err != nil {
		return fmt.Errorf("creating client: %v", err)
	}
	port := "8000/tcp"

	hostConfig := docker.HostConfig{
		PortBindings: map[string][]docker.PortBinding{
			port: []docker.PortBinding{
				// Docker will auto assign the port if left blank
				{HostIp: "0.0.0.0", HostPort: ""},
			},
		},
	}

	config := &docker.ContainerConfig{
		Image: "ubuntu:14.04",
		Cmd:   []string{"python3", "-m", "http.server"},
		ExposedPorts: map[string]struct{}{
			port: struct{}{},
		},
		HostConfig: hostConfig,
	}
	cid, err := cli.CreateContainer(config, "exposedporttest")
	if err != nil {
		return fmt.Errorf("creating container: %v", err)
	}
	defer func() {
		rcErr := cli.RemoveContainer(cid, true, false)
		if err == nil {
			err = rcErr
		} else if rcErr != nil {
			fmt.Fprintf(os.Stderr, "removing container %v\n", rcErr)
		}
	}()
	// start the container and get the port Docker assigned to it
	if err = cli.StartContainer(cid, &hostConfig); err != nil {
		return fmt.Errorf("start container: %v", err)
	}
	info, err := cli.InspectContainer(cid)
	if err != nil {
		return fmt.Errorf("inspect container: %v", err)
	}
	exposed, ok := info.NetworkSettings.Ports[port]
	if !ok {
		return fmt.Errorf("no ports exposed")
	}
	if len(exposed) != 1 {
		return fmt.Errorf("expected one exposed port, got %s", exposed)
	}
	hostIp, hostPort := exposed[0].HostIp, exposed[0].HostPort

	u := (&url.URL{
		Scheme: "http",
		Host:   hostIp + ":" + hostPort,
		Path:   "/",
	}).String()

	// give the simple http server a second to start up
	time.Sleep(500 * time.Millisecond)
	resp, err := http.Get(u)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("connecting to docker port %v", err)
	}
	return nil
}

// CheckInternetAccess confirms that processes within docker containers can
// access the outside internet by making a request to a PyPi JSON page and
// parsing the response.
func CheckInternetAccess() (err error) {
	cli, err := newClient()
	if err != nil {
		return fmt.Errorf("creating client: %v", err)
	}

	u := "https://pypi.python.org/pypi/yhat/json"
	// attempt to access a remote address
	cmd := `import urllib.request as r; print(r.urlopen("` + u + `").read().decode("utf-8"))`
	config := &docker.ContainerConfig{
		Image: "ubuntu:14.04",
		Cmd:   []string{"python3", "-c", cmd},
	}

	cid, err := cli.CreateContainer(config, "internetaccesstest")
	if err != nil {
		return fmt.Errorf("creating container: %v", err)
	}
	defer func() {
		rcErr := cli.RemoveContainer(cid, true, false)
		if err == nil {
			err = rcErr
		} else if rcErr != nil {
			fmt.Fprintf(os.Stderr, "removing container %v\n", rcErr)
		}
	}()

	// attach to the container
	streamOpts := &docker.AttachOptions{Stream: true, Stdout: true, Stderr: true}
	stream, err := cli.Attach(cid, streamOpts)
	if err != nil {
		return err
	}
	defer stream.Close()

	// start the container
	err = cli.StartContainer(cid, &docker.HostConfig{})
	if err != nil {
		return err
	}

	var stderr bytes.Buffer
	var stdout bytes.Buffer
	if err = docker.SplitStream(stream, &stdout, &stderr); err != nil {
		return fmt.Errorf("reading stdout: %v", err)
	}

	// wait for the container to exit
	exitCode, err := cli.Wait(cid)
	if err != nil {
		return err
	}

	if exitCode != 0 {
		return fmt.Errorf("bad exit code %d %s", exitCode, stderr)
	}

	var data struct {
		Info struct {
			HomePage string `json:"home_page"`
		} `json:"info"`
	}
	if err = json.Unmarshal(stdout.Bytes(), &data); err != nil {
		return fmt.Errorf("decoding JSON response from pypi: %v", err)
	}
	if data.Info.HomePage != "https://github.com/yhat/yhat-client" {
		return fmt.Errorf("bad JSON returned from %s", u)
	}
	if sErr := stderr.String(); sErr != "" {
		return fmt.Errorf("expected no response from stderr, got '%s'", sErr)
	}

	return nil
}

// CheckFileMounting confirms that docker can mount a file on the host machine
// into a container.
func CheckFileMounting() (err error) {
	cli, err := newClient()
	if err != nil {
		return fmt.Errorf("creating client: %v", err)
	}

	tempDir, err := ioutil.TempDir("", "")
	if err != nil {
		return fmt.Errorf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	fileName := "foo"

	file, err := os.Create(filepath.Join(tempDir, fileName))
	if err != nil {
		return fmt.Errorf("creating file: %v", err)
	}

	// write 1 KiB of random data to the file
	randData := make([]byte, 1<<10)
	if _, err = io.ReadFull(rand.Reader, randData); err != nil {
		return fmt.Errorf("reading random data: %v", err)
	}
	if _, err = file.Write(randData); err != nil {
		return fmt.Errorf("writing random data: %v", err)
	}

	targetDir := "/tmp/bar"
	targetFile := "/tmp/bar/" + fileName

	volumes := map[string]struct{}{targetDir: struct{}{}}
	bindings := []string{tempDir + ":" + targetDir}

	hostConfig := docker.HostConfig{Binds: bindings}

	config := &docker.ContainerConfig{
		Image:      "ubuntu:14.04",
		Cmd:        []string{"cat", targetFile},
		Volumes:    volumes,
		HostConfig: hostConfig,
	}
	cid, err := cli.CreateContainer(config, "filemounttest")
	if err != nil {
		return fmt.Errorf("creating container: %v", err)
	}
	defer func() {
		rcErr := cli.RemoveContainer(cid, true, false)
		if err == nil {
			err = rcErr
		} else if rcErr != nil {
			fmt.Fprintf(os.Stderr, "removing container %v\n", rcErr)
		}
	}()

	// attach to the container
	streamOpts := &docker.AttachOptions{Stream: true, Stdout: true, Stderr: true}
	stream, err := cli.Attach(cid, streamOpts)
	if err != nil {
		return err
	}
	defer stream.Close()

	// start the container
	err = cli.StartContainer(cid, &docker.HostConfig{})
	if err != nil {
		return err
	}

	var stderr bytes.Buffer
	var stdout bytes.Buffer
	if err = docker.SplitStream(stream, &stdout, &stderr); err != nil {
		return fmt.Errorf("reading stdout: %v", err)
	}

	// wait for the container to exit
	exitCode, err := cli.Wait(cid)
	if err != nil {
		return err
	}

	if exitCode != 0 {
		return fmt.Errorf("bad exit code %d %s", exitCode, stderr)
	}
	if bytes.Compare(stdout.Bytes(), randData) != 0 {
		return fmt.Errorf("mounted file did not match")
	}
	if sErr := stderr.String(); sErr != "" {
		return fmt.Errorf("expected no response from stderr, got '%s'", sErr)
	}

	return nil
}
