package archiver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/targodan/go-errors"
)

type remoteArchiver struct {
	url      string
	client   *http.Client
	reportID string
}

func NewRemoteArchiver(server string, reportName string) (Archiver, error) {
	client := &http.Client{}

	server = strings.TrimRight(server, "/")

	archiver := &remoteArchiver{
		url:    fmt.Sprintf("%s/v1", server),
		client: client,
	}
	err := archiver.create(reportName)
	if err != nil {
		return nil, err
	}

	return archiver, nil
}

func (a *remoteArchiver) prepareJson(data map[string]interface{}) (io.Reader, error) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	err := enc.Encode(data)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (a *remoteArchiver) postJson(endpoint string, data map[string]interface{}) (*http.Response, error) {
	buf, err := a.prepareJson(data)
	if err != nil {
		return nil, err
	}
	return a.client.Post(a.url+endpoint, "application/json", buf)
}

func (a *remoteArchiver) put(endpoint string) (*http.Response, error) {
	req, err := http.NewRequest("PUT", a.url+endpoint, &bytes.Buffer{})
	if err != nil {
		return nil, err
	}
	return a.client.Do(req)
}

func (a *remoteArchiver) patch(endpoint string, data []byte) (*http.Response, error) {
	buf := bytes.NewReader(data)
	req, err := http.NewRequest("PATCH", a.url+endpoint, buf)
	if err != nil {
		return nil, err
	}
	return a.client.Do(req)
}

func (a *remoteArchiver) closeResource(resource string) error {
	url := fmt.Sprintf("/report/%s", a.reportID)
	if resource != "" {
		url += "/" + resource
	}

	resp, err := a.put(url)
	if err != nil {
		return err
	}
	_, err = a.parseResponse(resp)
	return err
}

func (a *remoteArchiver) json(resp *http.Response) (map[string]interface{}, error) {
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	data := make(map[string]interface{})
	err := dec.Decode(&data)
	return data, err
}

func (a *remoteArchiver) extractErr(data map[string]interface{}) error {
	errTxt, ok := data["error"]
	if !ok {
		return fmt.Errorf("invalid response body")
	}
	if errTxt == nil {
		return nil
	}
	errString, ok := errTxt.(string)
	if !ok {
		return fmt.Errorf("invalid response body")
	}
	return errors.New(errString)
}

func (a *remoteArchiver) parseResponse(resp *http.Response) (map[string]interface{}, error) {
	data, err := a.json(resp)
	if err != nil {
		return nil, err
	}
	err = a.extractErr(data)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected http status: %s", resp.Status)
	}
	return data, nil
}

func (a *remoteArchiver) create(reportName string) error {
	resp, err := a.postJson("/report", map[string]interface{}{
		"name": reportName,
	})
	if err != nil {
		return err
	}
	data, err := a.parseResponse(resp)
	reportID, ok := data["reportID"]
	if !ok {
		return fmt.Errorf("invalid response body")
	}
	reportIDStr, ok := reportID.(string)
	if !ok {
		return fmt.Errorf("invalid response body")
	}

	a.reportID = reportIDStr
	return nil
}

func (a *remoteArchiver) Create(name string) (io.WriteCloser, error) {
	name = filepath.ToSlash(name)
	resp, err := a.postJson(fmt.Sprintf("/report/%s/%s", a.reportID, name), map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	_, err = a.parseResponse(resp)
	if err != nil {
		return nil, err
	}
	return &remoteFile{
		archiver: a,
		filepath: name,
	}, nil
}

func (a *remoteArchiver) Close() error {
	return a.closeResource("")
}

type remoteFile struct {
	archiver *remoteArchiver
	filepath string
}

func (f *remoteFile) Write(d []byte) (int, error) {
	resp, err := f.archiver.patch(fmt.Sprintf("/report/%s/%s", f.archiver.reportID, f.filepath), d)
	if err != nil {
		return 0, err
	}
	_, err = f.archiver.parseResponse(resp)
	if err != nil {
		return 0, err
	}
	return len(d), nil
}

func (f *remoteFile) Close() error {
	return f.archiver.closeResource(f.filepath)
}
