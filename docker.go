package docker

import (
	"archive/tar"
	"bytes"
	"crypto/tls"
	"encoding/base64"
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

func (e *Error) Error() string {
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
		TLSClientConfig:   tlsConfig,
		DisableKeepAlives: true,
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

func (client *Client) DoRequest(method string, path string, body io.Reader) (*http.Response, error) {
	req, err := client.NewRequest(method, path, body)
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
	if resp.StatusCode >= 400 {
		data, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read body from response: %v", err)
		}
		return nil, &Error{StatusCode: resp.StatusCode, Status: resp.Status, msg: string(data)}
	}
	return resp, nil
}

func (client *Client) NewRequest(method string, path string, body io.Reader) (*http.Request, error) {
	return http.NewRequest(method, client.URL.String()+path, body)
}

// jsonUnmarshal reads the full body from the response and attempts to unmarshal
// the result into the value v.
// For convenience it also closes the response body.
func jsonUnmarshal(resp *http.Response, v interface{}) error {
	data, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("failed to read body from response: %v", err)
	}
	return json.Unmarshal(data, v)
}

func (client *Client) Info() (*Info, error) {
	uri := fmt.Sprintf("/%s/info", APIVersion)
	data, err := client.DoRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}
	ret := &Info{}
	err = jsonUnmarshal(data, &ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (client *Client) Push(name, tag string, auth *AuthConfig) error {
	data, err := json.Marshal(auth)
	if err != nil {
		return err
	}
	authHeader := base64.URLEncoding.EncodeToString(data)
	path := "/images/" + name + "/push"
	if tag != "" {
		path = path + "?" + (url.Values{"tag": []string{tag}}).Encode()
	}

	req, err := client.NewRequest("POST", "/images/"+name+"/push", nil)
	if err != nil {
		return err
	}
	req.Header.Add("X-Registry-Auth", authHeader)
	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read body from response: %v", err)
		}
		return &Error{StatusCode: resp.StatusCode, Status: resp.Status, msg: string(data)}
	}

	decoder := json.NewDecoder(resp.Body)
	for {
		var s struct {
			Error string `json:"error"`
		}
		if err := decoder.Decode(&s); err != nil {
			if err == io.EOF {
				// Don't know if this is the correct logic, but the documentation
				// on the remote api doesn't actually describe how to ensure a
				// push is successful as of v1.20
				return nil
			}
			return err
		}
		if s.Error != "" {
			return errors.New(s.Error)
		}
	}
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

	data, err := client.DoRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}
	ret := []Container{}
	err = jsonUnmarshal(data, &ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (client *Client) InspectContainer(id string) (*ContainerInfo, error) {
	uri := fmt.Sprintf("/%s/containers/%s/json", APIVersion, id)
	data, err := client.DoRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}
	info := &ContainerInfo{}
	err = jsonUnmarshal(data, info)
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
	resp, err := client.DoRequest("POST", uri, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	result := &RespContainersCreate{}
	err = jsonUnmarshal(resp, result)
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
	resp, err := client.DoRequest("POST", uri, bytes.NewReader(data))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (client *Client) StopContainer(id string, timeout int) error {
	uri := fmt.Sprintf("/%s/containers/%s/stop?t=%d", APIVersion, id, timeout)
	resp, err := client.DoRequest("POST", uri, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (client *Client) RestartContainer(id string, timeout int) error {
	uri := fmt.Sprintf("/%s/containers/%s/restart?t=%d", APIVersion, id, timeout)
	resp, err := client.DoRequest("POST", uri, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (client *Client) KillContainer(id, signal string) error {
	uri := fmt.Sprintf("/%s/containers/%s/kill?signal=%s", APIVersion, id, signal)
	resp, err := client.DoRequest("POST", uri, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (client *Client) Version() (*Version, error) {
	uri := fmt.Sprintf("/%s/version", APIVersion)
	data, err := client.DoRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}
	version := &Version{}
	err = jsonUnmarshal(data, version)
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
		return &Error{StatusCode: resp.StatusCode, Status: resp.Status, msg: string(data)}
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
	resp, err := client.DoRequest("DELETE", uri, nil)
	if err == nil {
		resp.Body.Close()
	}
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
	data, err := client.DoRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}
	var images []*Image
	if err := jsonUnmarshal(data, &images); err != nil {
		return nil, err
	}
	return images, nil
}

func (client *Client) RemoveImage(name string) ([]*ImageDelete, error) {
	uri := fmt.Sprintf("/%s/images/%s", APIVersion, name)
	data, err := client.DoRequest("DELETE", uri, nil)
	if err != nil {
		return nil, err
	}
	var imageDelete []*ImageDelete
	if err := jsonUnmarshal(data, &imageDelete); err != nil {
		return nil, err
	}
	return imageDelete, nil
}

func (client *Client) PauseContainer(id string) error {
	uri := fmt.Sprintf("/%s/containers/%s/pause", APIVersion, id)
	resp, err := client.DoRequest("POST", uri, nil)
	if err == nil {
		resp.Body.Close()
	}
	return err
}
func (client *Client) UnpauseContainer(id string) error {
	uri := fmt.Sprintf("/%s/containers/%s/unpause", APIVersion, id)
	resp, err := client.DoRequest("POST", uri, nil)
	if err == nil {
		resp.Body.Close()
	}
	return err
}

func (client *Client) Exec(config *ExecConfig) (string, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	uri := fmt.Sprintf("/containers/%s/exec", config.Container)
	resp, err := client.DoRequest("POST", uri, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	var createExecResp struct {
		Id string
	}
	if err = jsonUnmarshal(resp, &createExecResp); err != nil {
		return "", err
	}
	uri = fmt.Sprintf("/exec/%s/start", createExecResp.Id)
	resp, err = client.DoRequest("POST", uri, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	return createExecResp.Id, nil
}

func (client *Client) InspectImage(name string) (ImageInfo, error) {
	uri := fmt.Sprintf("/images/%s/json", name)
	resp, err := client.DoRequest("GET", uri, nil)
	if err != nil {
		return ImageInfo{}, err
	}
	img := ImageInfo{}
	if err := jsonUnmarshal(resp, &img); err != nil {
		return ImageInfo{}, fmt.Errorf("docker: InspectImage: %v", err)
	}
	return img, nil
}

func (client *Client) History(id string) ([]ImageLayer, error) {
	uri := fmt.Sprintf("%s/images/%s/history", APIVersion, id)
	data, err := client.DoRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}
	layers := []ImageLayer{}
	err = jsonUnmarshal(data, &layers)
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
	uri := "/commit?" + values.Encode()
	resp, err := client.DoRequest("POST", uri, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	var commitResp struct {
		Id string
	}
	if err = jsonUnmarshal(resp, &commitResp); err != nil {
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
	resp, err := client.DoRequest("POST", uri, nil)
	if err == nil {
		resp.Body.Close()
	}
	return err
}

// Changes provides a list of changes made to a container.
func (client *Client) Changes(cid string) ([]ContainerChange, error) {
	uri := fmt.Sprintf("/containers/%s/changes", cid)
	resp, err := client.DoRequest("GET", uri, nil)
	var changes []ContainerChange
	if err != nil {
		return changes, err
	}
	if err = jsonUnmarshal(resp, &changes); err != nil {
		return changes, fmt.Errorf("docker: changes: %v", err)
	}
	return changes, nil
}

// TarReader wraps tar.Reader with a close method.
type TarReader struct {
	*tar.Reader
	c io.Closer
}

func (tr TarReader) Close() error {
	return tr.c.Close()
}

// Copy copies files or folders from a container.
// It is the caller's responsiblity to call Close on returned TarReader.
func (client *Client) Copy(cid, resource string) (TarReader, error) {
	data, err := json.Marshal(map[string]string{"Resource": resource})
	if err != nil {
		return TarReader{}, err
	}

	uri := fmt.Sprintf("/containers/%s/copy", cid)

	resp, err := client.DoRequest("POST", uri, bytes.NewReader(data))
	if err != nil {
		return TarReader{}, err
	}
	return TarReader{
		tar.NewReader(resp.Body),
		resp.Body,
	}, nil
}

// Wait blocks until a container has exited. Wait returns the StatusCode of the
// exited process.
func (client *Client) Wait(cid string) (int, error) {
	uri := fmt.Sprintf("/containers/%s/wait", cid)
	resp, err := client.DoRequest("POST", uri, nil)
	if err != nil {
		return 0, err
	}
	waitResp := struct {
		StatusCode int
	}{-1}
	if err := jsonUnmarshal(resp, &waitResp); err != nil {
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

func (client *Client) MonitorStats(id string) (*Stats, error) {

	uri := fmt.Sprintf("%s/containers/%s/stats?stream=0", client.URL.String(), id)
	resp, err := client.HTTPClient.Get(uri)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, &Error{StatusCode: resp.StatusCode,
			Status: resp.Status, msg: string(data)}
	}
	var stats *Stats
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&stats); err != nil {
		return nil, fmt.Errorf("could not decode stats: %v", err)
	}
	return stats, nil
}
