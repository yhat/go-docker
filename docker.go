package docker

import (
	"bytes"
	"crypto/tls"
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

func (client *Client) ListImages() ([]*Image, error) {
	uri := fmt.Sprintf("/%s/images/json", APIVersion)
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
