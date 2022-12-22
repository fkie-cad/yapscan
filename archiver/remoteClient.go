package archiver

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/targodan/go-errors"
)

type RemoteArchiver struct {
	url             string
	client          *http.Client
	clientTLSConfig *tls.Config
	reportID        string
}

func NewRemoteArchiver(server string) (*RemoteArchiver, error) {
	client := &http.Client{}

	server = strings.TrimRight(server, "/")

	archiver := &RemoteArchiver{
		url:    fmt.Sprintf("%s/v1", server),
		client: client,
	}

	return archiver, nil
}

func (a *RemoteArchiver) InitReport(reportName string) error {
	return a.create(reportName)
}

func (a *RemoteArchiver) defaultTLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13}
}

func (a *RemoteArchiver) SetServerCA(filepath string) error {
	if a.clientTLSConfig == nil {
		a.clientTLSConfig = a.defaultTLSConfig()
	}

	file, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("could not open server CA file, reason: %w", err)
	}

	caPool, err := loadCA(file)
	if err != nil {
		return err
	}
	a.clientTLSConfig.RootCAs = caPool

	a.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: a.clientTLSConfig,
		},
	}
	return nil
}

func (a *RemoteArchiver) SetClientCert(certPath, keyPath string) error {
	if a.clientTLSConfig == nil {
		a.clientTLSConfig = a.defaultTLSConfig()
	}

	cert, err := os.Open(certPath)
	if err != nil {
		return fmt.Errorf("could not open certificate file, reason: %w", err)
	}
	key, err := os.Open(keyPath)
	if err != nil {
		return fmt.Errorf("could not open key file, reason: %w", err)
	}

	keypair, err := loadX509KeyPair(cert, key)
	if err != nil {
		return err
	}
	a.clientTLSConfig.Certificates = []tls.Certificate{keypair}

	a.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: a.clientTLSConfig,
		},
	}
	return nil
}

func (a *RemoteArchiver) prepareJson(data map[string]interface{}) (io.Reader, error) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	err := enc.Encode(data)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (a *RemoteArchiver) postJson(endpoint string, data map[string]interface{}) (*http.Response, error) {
	buf, err := a.prepareJson(data)
	if err != nil {
		return nil, err
	}
	return a.client.Post(a.url+endpoint, "application/json", buf)
}

func (a *RemoteArchiver) put(endpoint string) (*http.Response, error) {
	req, err := http.NewRequest("PUT", a.url+endpoint, &bytes.Buffer{})
	if err != nil {
		return nil, err
	}
	return a.client.Do(req)
}

func (a *RemoteArchiver) patch(endpoint string, data []byte) (*http.Response, error) {
	buf := bytes.NewReader(data)
	req, err := http.NewRequest("PATCH", a.url+endpoint, buf)
	if err != nil {
		return nil, err
	}
	return a.client.Do(req)
}

func (a *RemoteArchiver) closeResource(resource string) error {
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

func (a *RemoteArchiver) json(resp *http.Response) (map[string]interface{}, error) {
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	data := make(map[string]interface{})
	err := dec.Decode(&data)
	return data, err
}

func (a *RemoteArchiver) extractErr(data map[string]interface{}) error {
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

func (a *RemoteArchiver) parseResponse(resp *http.Response) (map[string]interface{}, error) {
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

func (a *RemoteArchiver) create(reportName string) error {
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

func (a *RemoteArchiver) Create(name string) (io.WriteCloser, error) {
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

func (a *RemoteArchiver) Close() error {
	return a.closeResource("")
}

type remoteFile struct {
	archiver *RemoteArchiver
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
