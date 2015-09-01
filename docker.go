package docker

import (
	"archive/tar"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const APIVersion = "v1.17"

var ErrNotFound = errors.New("Not found")

type Client struct {
	URL        *url.URL
	HTTPClient *http.Client
	TLSConfig  *tls.Config
}

type Error struct {
	StatusCode int
	Status     string
	msg        string
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Status, e.msg)
}

func NewClient(daemonURL string, tlsConfig *tls.Config, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(daemonURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Scheme == "tcp" {
		if tlsConfig == nil {
			u.Scheme = "http"
		} else {
			u.Scheme = "https"
		}
	}
	httpClient := newHTTPClient(u, tlsConfig, timeout)
	return &Client{u, httpClient, tlsConfig}, nil
}

func newHTTPClient(u *url.URL, tlsConfig *tls.Config, timeout time.Duration) *http.Client {
	httpTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	switch u.Scheme {
	default:
		httpTransport.Dial = func(proto, addr string) (net.Conn, error) {
			return net.DialTimeout(proto, addr, timeout)
		}
	case "unix":
		socketPath := u.Path
		unixDial := func(proto, addr string) (net.Conn, error) {
			return net.DialTimeout("unix", socketPath, timeout)
		}
		httpTransport.Dial = unixDial
		// Override the main URL object so the HTTP lib won't complain
		u.Scheme = "http"
		u.Host = "unix.sock"
		u.Path = ""
	}
	return &http.Client{Transport: httpTransport}
}

func (client *Client) doRequest(method string, path string, body []byte) ([]byte, error) {
	b := bytes.NewBuffer(body)
	req, err := http.NewRequest(method, client.URL.String()+path, b)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		if !strings.Contains(err.Error(), "connection refused") && client.TLSConfig == nil {
			return nil, fmt.Errorf("%v. Are you trying to connect to a TLS-enabled daemon without TLS?", err)
		}
		return nil, err
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 404 {
		return nil, ErrNotFound
	}
	if resp.StatusCode >= 400 {
		return nil, Error{StatusCode: resp.StatusCode, Status: resp.Status, msg: string(data)}
	}
	return data, nil
}

func (client *Client) Info() (*Info, error) {
	uri := fmt.Sprintf("/%s/info", APIVersion)
	data, err := client.doRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}
	ret := &Info{}
	err = json.Unmarshal(data, &ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (client *Client) ListContainers(all bool, size bool, filters string) ([]Container, error) {
	argAll := 0
	if all == true {
		argAll = 1
	}
	showSize := 0
	if size == true {
		showSize = 1
	}
	uri := fmt.Sprintf("/%s/containers/json?all=%d&size=%d", APIVersion, argAll, showSize)

	if filters != "" {
		uri += "&filters=" + filters
	}

	data, err := client.doRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}
	ret := []Container{}
	err = json.Unmarshal(data, &ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (client *Client) InspectContainer(id string) (*ContainerInfo, error) {
	uri := fmt.Sprintf("/%s/containers/%s/json", APIVersion, id)
	data, err := client.doRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}
	info := &ContainerInfo{}
	err = json.Unmarshal(data, info)
	if err != nil {
		return nil, err
	}
	return info, nil
}

func (client *Client) CreateContainer(config *ContainerConfig, name string) (string, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	uri := fmt.Sprintf("/%s/containers/create", APIVersion)
	if name != "" {
		v := url.Values{}
		v.Set("name", name)
		uri = fmt.Sprintf("%s?%s", uri, v.Encode())
	}
	data, err = client.doRequest("POST", uri, data)
	if err != nil {
		return "", err
	}
	result := &RespContainersCreate{}
	err = json.Unmarshal(data, result)
	if err != nil {
		return "", err
	}
	return result.Id, nil
}

func (client *Client) ContainerLogs(id string, options *LogOptions) (io.ReadCloser, error) {
	v := url.Values{}
	v.Add("follow", strconv.FormatBool(options.Follow))
	v.Add("stdout", strconv.FormatBool(options.Stdout))
	v.Add("stderr", strconv.FormatBool(options.Stderr))
	v.Add("timestamps", strconv.FormatBool(options.Timestamps))
	if options.Tail > 0 {
		v.Add("tail", strconv.FormatInt(options.Tail, 10))
	}

	uri := fmt.Sprintf("/%s/containers/%s/logs?%s", APIVersion, id, v.Encode())
	req, err := http.NewRequest("GET", client.URL.String()+uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (client *Client) StartContainer(id string, config *HostConfig) error {
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	uri := fmt.Sprintf("/%s/containers/%s/start", APIVersion, id)
	_, err = client.doRequest("POST", uri, data)
	if err != nil {
		return err
	}
	return nil
}

func (client *Client) StopContainer(id string, timeout int) error {
	uri := fmt.Sprintf("/%s/containers/%s/stop?t=%d", APIVersion, id, timeout)
	_, err := client.doRequest("POST", uri, nil)
	if err != nil {
		return err
	}
	return nil
}

func (client *Client) RestartContainer(id string, timeout int) error {
	uri := fmt.Sprintf("/%s/containers/%s/restart?t=%d", APIVersion, id, timeout)
	_, err := client.doRequest("POST", uri, nil)
	if err != nil {
		return err
	}
	return nil
}

func (client *Client) KillContainer(id, signal string) error {
	uri := fmt.Sprintf("/%s/containers/%s/kill?signal=%s", APIVersion, id, signal)
	_, err := client.doRequest("POST", uri, nil)
	if err != nil {
		return err
	}
	return nil
}

func (client *Client) Version() (*Version, error) {
	uri := fmt.Sprintf("/%s/version", APIVersion)
	data, err := client.doRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}
	version := &Version{}
	err = json.Unmarshal(data, version)
	if err != nil {
		return nil, err
	}
	return version, nil
}

func (client *Client) PullImage(name string, auth *AuthConfig) error {
	v := url.Values{}
	v.Set("fromImage", name)
	uri := fmt.Sprintf("/%s/images/create?%s", APIVersion, v.Encode())
	req, err := http.NewRequest("POST", client.URL.String()+uri, nil)
	if auth != nil {
		req.Header.Add("X-Registry-Auth", auth.encode())
	}
	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var finalObj map[string]interface{}
	for decoder := json.NewDecoder(resp.Body); err == nil; err = decoder.Decode(&finalObj) {
	}
	if err != io.EOF {
		return err
	}
	if err, ok := finalObj["error"]; ok {
		return fmt.Errorf("%v", err)
	}
	return nil
}

func (client *Client) LoadImage(reader io.Reader) error {
	uri := fmt.Sprintf("/%s/images/load", APIVersion)
	req, err := http.NewRequest("POST", client.URL.String()+uri, reader)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return Error{StatusCode: resp.StatusCode, Status: resp.Status, msg: string(data)}
	}
	return nil
}

func (client *Client) RemoveContainer(id string, force, volumes bool) error {
	argForce := 0
	argVolumes := 0
	if force == true {
		argForce = 1
	}
	if volumes == true {
		argVolumes = 1
	}
	args := fmt.Sprintf("force=%d&v=%d", argForce, argVolumes)
	uri := fmt.Sprintf("/%s/containers/%s?%s", APIVersion, id, args)
	_, err := client.doRequest("DELETE", uri, nil)
	return err
}

func (client *Client) ListImages(all bool) ([]*Image, error) {
	vals := url.Values{}
	if all {
		vals.Set("all", "1")
	}
	uri := fmt.Sprintf("/%s/images/json", APIVersion)
	if len(vals) > 0 {
		uri = uri + "?" + vals.Encode()
	}
	data, err := client.doRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}
	var images []*Image
	if err := json.Unmarshal(data, &images); err != nil {
		return nil, err
	}
	return images, nil
}

func (client *Client) RemoveImage(name string) ([]*ImageDelete, error) {
	uri := fmt.Sprintf("/%s/images/%s", APIVersion, name)
	data, err := client.doRequest("DELETE", uri, nil)
	if err != nil {
		return nil, err
	}
	var imageDelete []*ImageDelete
	if err := json.Unmarshal(data, &imageDelete); err != nil {
		return nil, err
	}
	return imageDelete, nil
}

func (client *Client) PauseContainer(id string) error {
	uri := fmt.Sprintf("/%s/containers/%s/pause", APIVersion, id)
	_, err := client.doRequest("POST", uri, nil)
	if err != nil {
		return err
	}
	return nil
}
func (client *Client) UnpauseContainer(id string) error {
	uri := fmt.Sprintf("/%s/containers/%s/unpause", APIVersion, id)
	_, err := client.doRequest("POST", uri, nil)
	if err != nil {
		return err
	}
	return nil
}

func (client *Client) Exec(config *ExecConfig) (string, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	uri := fmt.Sprintf("/containers/%s/exec", config.Container)
	resp, err := client.doRequest("POST", uri, data)
	if err != nil {
		return "", err
	}
	var createExecResp struct {
		Id string
	}
	if err = json.Unmarshal(resp, &createExecResp); err != nil {
		return "", err
	}
	uri = fmt.Sprintf("/exec/%s/start", createExecResp.Id)
	resp, err = client.doRequest("POST", uri, data)
	if err != nil {
		return "", err
	}
	return createExecResp.Id, nil
}

func (client *Client) InspectImage(name string) (ImageInfo, error) {
	uri := fmt.Sprintf("/images/%s/json", name)
	resp, err := client.doRequest("GET", uri, nil)
	if err != nil {
		return ImageInfo{}, err
	}
	img := ImageInfo{}
	if err := json.Unmarshal(resp, &img); err != nil {
		return ImageInfo{}, fmt.Errorf("docker: InspectImage: %v", err)
	}
	return img, nil
}

func (client *Client) History(id string) ([]ImageLayer, error) {
	uri := fmt.Sprintf("%s/images/%s/history", APIVersion, id)
	data, err := client.doRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}
	layers := []ImageLayer{}
	err = json.Unmarshal(data, &layers)
	if err != nil {
		return nil, err
	}
	return layers, nil
}

func (client *Client) Commit(options *CommitOptions, config *ContainerConfig) (string, error) {

	values := url.Values{}
	add := func(name, val string) {
		if val != "" {
			values.Add(name, val)
		}
	}
	add("container", options.Container)
	add("repo", options.Repo)
	add("tag", options.Tag)
	add("comment", options.Comment)
	add("author", options.Author)

	data, err := json.Marshal(&config)
	if err != nil {
		return "", err
	}
	uri := fmt.Sprintf("/commit?" + values.Encode())
	resp, err := client.doRequest("POST", uri, data)
	if err != nil {
		return "", err
	}
	var commitResp struct {
		Id string
	}
	if err = json.Unmarshal(resp, &commitResp); err != nil {
		return "", fmt.Errorf("docker: commit: %v", err)
	}
	if commitResp.Id == "" {
		return "", fmt.Errorf("docker: commit: response did not have Id field")
	}
	return commitResp.Id, nil
}

func (client *Client) Tag(imgId string, ops *TagOptions) error {
	values := url.Values{}
	if ops.Repo != "" {
		values.Add("repo", ops.Repo)
	}
	if ops.Tag != "" {
		values.Add("tag", ops.Tag)
	}
	values.Add("force", strconv.FormatBool(ops.Force))
	// urlencode image id
	imgId = (&url.URL{Path: imgId}).String()

	uri := fmt.Sprintf("/images/%s/tag?%s", imgId, values.Encode())
	_, err := client.doRequest("POST", uri, nil)
	// doRequest checks for a 200
	return err
}

// Changes provides a list of changes made to a container.
func (client *Client) Changes(cid string) ([]ContainerChange, error) {
	uri := fmt.Sprintf("/containers/%s/changes", cid)
	resp, err := client.doRequest("GET", uri, nil)
	var changes []ContainerChange
	if err != nil {
		return changes, err
	}
	if err = json.Unmarshal(resp, &changes); err != nil {
		return changes, fmt.Errorf("docker: changes: %v", err)
	}
	return changes, nil
}

// Copy copies files or folders from a container.
func (client *Client) Copy(cid, resource string) (*tar.Reader, error) {
	data, err := json.Marshal(map[string]string{"Resource": resource})
	if err != nil {
		return nil, err
	}

	uri := fmt.Sprintf("/containers/%s/copy", cid)

	resp, err := client.doRequest("POST", uri, data)
	if err != nil {
		return nil, err
	}

	return tar.NewReader(bytes.NewReader(resp)), nil
}

// Wait blocks until a container has exited. Wait returns the StatusCode of the
// exited process.
func (client *Client) Wait(cid string) (int, error) {
	uri := fmt.Sprintf("/containers/%s/wait", cid)
	resp, err := client.doRequest("POST", uri, nil)
	if err != nil {
		return 0, err
	}
	waitResp := struct {
		StatusCode int
	}{-1}
	if err := json.Unmarshal(resp, &waitResp); err != nil {
		return 0, fmt.Errorf("docker: wait: %v", err)
	}
	return waitResp.StatusCode, nil
}

// Attach returns the stdout and stderr stream of a stopped or running
// container. It is the callers responsibility to close the returned stream.
// Use SplitStream to parse stdout and stderr.
func (client *Client) Attach(cid string, options *AttachOptions) (io.ReadCloser, error) {
	values := url.Values{}
	add := func(name string, val bool) {
		values.Add(name, strconv.FormatBool(val))
	}
	add("logs", options.Logs)
	add("stream", options.Stream)
	add("stdin", options.Stdin)
	add("stdout", options.Stdout)
	add("stderr", options.Stderr)

	p := fmt.Sprintf("/containers/%s/attach?%s", cid, values.Encode())
	req, err := http.NewRequest("POST", client.URL.String()+p, nil)
	if err != nil {
		return nil, fmt.Errorf("could not construct request to docker")
	}
	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		if !strings.Contains(err.Error(), "connection refused") && client.TLSConfig == nil {
			return nil, fmt.Errorf("%v. Are you trying to connect to a TLS-enabled daemon without TLS?", err)
		}
		return nil, err
	}
	if resp.StatusCode == http.StatusOK {
		return resp.Body, nil
	}

	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusSwitchingProtocols:
		return nil, fmt.Errorf("docker: attach: did not send websocket request but got 101 back")
	case http.StatusBadRequest:
		// Probably shouldn't get here
		return nil, fmt.Errorf("docker: attach: invalid request parameters")
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusInternalServerError:
		return nil, fmt.Errorf("docker: attach: internal server error")
	default:
		return nil, fmt.Errorf("docker: attach: unexpected status code %s", resp.Status)
	}
}

const (
	StdinStream  byte = 0
	StdoutStream      = 1
	StderrStream      = 2
)

// SplitStream splits docker stream data into stdout and stderr.
// For specifications see http://goo.gl/Dnbcye
func SplitStream(stream io.Reader, stdout, stderr io.Writer) error {
	header := make([]byte, 8)
	for {
		if _, err := io.ReadFull(stream, header); err != nil {
			if err == io.EOF {
				return nil
			} else {
				return fmt.Errorf("could not read header: %v", err)
			}
		}

		var dest io.Writer
		switch header[0] {
		case StdinStream, StdoutStream:
			dest = stdout
		case StderrStream:
			dest = stderr
		default:
			return fmt.Errorf("bad STREAM_TYPE given: %x", header[0])
		}

		frameSize := int64(binary.BigEndian.Uint32(header[4:]))
		if _, err := io.CopyN(dest, stream, frameSize); err != nil {
			return fmt.Errorf("copying stream payload failed: %v", err)
		}
	}
}
