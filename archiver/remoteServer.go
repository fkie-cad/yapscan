package archiver

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/targodan/go-errors"

	"github.com/gin-gonic/gin"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type WriteCloserBuilder interface {
	Build(closer io.WriteCloser) (io.WriteCloser, error)
}

func generateReportID() string {
	buf := make([]byte, 32)
	rand.Read(buf)
	hash := sha256.New()
	hash.Write(buf)
	return hex.EncodeToString(hash.Sum(nil))
}

func handleError(c *gin.Context, err error) bool {
	if err != nil {
		logrus.WithError(err).Error("Error during handling of request.")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return true
	}
	return false
}

func sendOkay(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"error": nil})
}

type ArchiverServer struct {
	router    *gin.Engine
	server    *http.Server
	outdir    string
	outerExt  string
	wcBuilder WriteCloserBuilder

	reportsMux  *sync.RWMutex
	openReports map[string]*reportHandler
}

func NewArchiverServer(addr, outdir, outerExt string, builder WriteCloserBuilder) *ArchiverServer {
	router := gin.Default()
	router.SetTrustedProxies([]string{})
	router.Use()

	s := &ArchiverServer{
		router:      router,
		outdir:      outdir,
		outerExt:    outerExt,
		wcBuilder:   builder,
		reportsMux:  &sync.RWMutex{},
		openReports: make(map[string]*reportHandler),
	}

	v1 := router.Group("/v1")

	v1.POST("/report", s.createReport)
	v1.PUT("/report/:report", s.closeReport)
	v1.POST("/report/:report/*filepath", s.createFile)
	v1.PATCH("/report/:report/*filepath", s.writeFile)
	v1.PUT("/report/:report/*filepath", s.closeFile)

	s.server = &http.Server{
		Addr:    addr,
		Handler: router,
	}

	return s
}

func (s *ArchiverServer) Start() error {
	if s.server.TLSConfig != nil {
		return s.server.ListenAndServeTLS("", "")
	} else {
		return s.server.ListenAndServe()
	}
}

func loadX509KeyPair(cert, key io.Reader) (tls.Certificate, error) {
	certBlock, err := io.ReadAll(cert)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not read certificate, reason: %w", err)
	}
	keyBlock, err := io.ReadAll(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not read key, reason: %w", err)
	}
	return tls.X509KeyPair(certBlock, keyBlock)
}

func loadCA(ca io.Reader) (*x509.CertPool, error) {
	caBlock, err := io.ReadAll(ca)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caBlock) {
		return nil, fmt.Errorf("could not register CA certificate")
	}
	return certPool, nil
}

func getTLSConfig(serverCert, serverKey, clientCA string) (*tls.Config, error) {
	cert, err := os.Open(serverCert)
	if err != nil {
		return nil, fmt.Errorf("could not open server-cert file, reason: %w", err)
	}
	defer cert.Close()
	key, err := os.Open(serverKey)
	if err != nil {
		return nil, fmt.Errorf("could not open server-key file, reason: %w", err)
	}
	defer key.Close()

	serverKeypair, err := loadX509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}

	var certPool *x509.CertPool
	clientAuth := tls.NoClientCert
	if clientCA != "" {
		ca, err := os.Open(clientCA)
		if err != nil {
			return nil, fmt.Errorf("could not open client-ca file, reason: %w", err)
		}
		defer ca.Close()

		certPool, err = loadCA(ca)
		if err != nil {
			return nil, err
		}

		clientAuth = tls.RequireAndVerifyClientCert
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{serverKeypair},
		ClientAuth:   clientAuth,
		MinVersion:   tls.VersionTLS13,
		ClientCAs:    certPool,
	}

	return config, nil
}

func (s *ArchiverServer) EnableTLS(serverCert, serverKey, clientCA string) error {
	var err error
	s.server.TLSConfig, err = getTLSConfig(serverCert, serverKey, clientCA)
	return err
}

func (s *ArchiverServer) Shutdown(ctx context.Context) error {
	err := s.server.Shutdown(ctx)

	s.reportsMux.Lock()
	defer s.reportsMux.Unlock()

	for id, report := range s.openReports {
		e := report.Close()
		if e != nil {
			logrus.WithError(e).Errorf("Error during final close of report with ID '%s'", id)
			err = errors.NewMultiError(err, e)
		}
		logrus.Infof("Closed report with ID '%s'", id)
	}

	s.openReports = nil
	return err
}

func (s *ArchiverServer) registerReport(reportID, reportName string) (*reportHandler, error) {
	s.reportsMux.Lock()
	defer s.reportsMux.Unlock()

	_, exists := s.openReports[reportID]
	if exists {
		return nil, fmt.Errorf("report with ID '%s' already exists", sanitizeStringForLogs(reportID))
	}

	handler, err := newReportHandler(s.outdir, reportName, s.outerExt, s.wcBuilder)
	if err != nil {
		return nil, err
	}
	s.openReports[reportID] = handler

	return handler, nil
}

func (s *ArchiverServer) getReport(reportID string) (*reportHandler, error) {
	s.reportsMux.RLock()
	defer s.reportsMux.RUnlock()

	report, exists := s.openReports[reportID]
	if !exists {
		return nil, fmt.Errorf("report with ID '%s' does not exists", sanitizeStringForLogs(reportID))
	}
	return report, nil
}

func (s *ArchiverServer) getAndRemoveReport(reportID string) (*reportHandler, error) {
	s.reportsMux.Lock()
	defer s.reportsMux.Unlock()

	report, exists := s.openReports[reportID]
	if !exists {
		return nil, fmt.Errorf("report with ID '%s' does not exists", sanitizeStringForLogs(reportID))
	}
	delete(s.openReports, reportID)

	return report, nil
}

type CreateReportRequest struct {
	Name string `json:"name"`
}

func sanitizeFilename(name string) string {
	return path.Base(path.Clean("/" + removeNewlines(name)))
}

func (s *ArchiverServer) createReport(c *gin.Context) {
	var req CreateReportRequest
	if err := c.ShouldBindJSON(&req); handleError(c, err) {
		return
	}

	reportName := sanitizeFilename(req.Name)
	if reportName == "." || reportName == "/" {
		handleError(c, fmt.Errorf("invalid report name '%s'", sanitizeStringForLogs(req.Name)))
		return
	}

	reportID := generateReportID()
	_, err := s.registerReport(reportID, reportName)
	if handleError(c, err) {
		return
	}

	logrus.Infof("Creating new report '%s' with ID '%s'", sanitizeStringForLogs(req.Name), reportID)

	c.JSON(http.StatusOK, gin.H{
		"error":    nil,
		"reportID": reportID,
	})
}

func (s *ArchiverServer) closeReport(c *gin.Context) {
	report, err := s.getAndRemoveReport(c.Param("report"))
	if handleError(c, err) {
		return
	}
	if handleError(c, report.Close()) {
		return
	}
	logrus.Infof("Closed report with ID '%s'", sanitizeStringForLogs(c.Param("report")))
	sendOkay(c)
}

func (s *ArchiverServer) createFile(c *gin.Context) {
	report, err := s.getReport(c.Param("report"))
	if handleError(c, err) {
		return
	}

	err = report.CreateFile(c.Param("filepath"))
	if handleError(c, err) {
		return
	}

	sendOkay(c)
}

func (s *ArchiverServer) writeFile(c *gin.Context) {
	report, err := s.getReport(c.Param("report"))
	if handleError(c, err) {
		return
	}

	data, err := c.GetRawData()
	if handleError(c, err) {
		return
	}

	err = report.WriteFile(c.Param("filepath"), data)
	if handleError(c, err) {
		return
	}

	sendOkay(c)
}

func (s *ArchiverServer) closeFile(c *gin.Context) {
	report, err := s.getReport(c.Param("report"))
	if handleError(c, err) {
		return
	}

	err = report.CloseFile(c.Param("filepath"))
	if handleError(c, err) {
		return
	}

	sendOkay(c)
}

type reportHandler struct {
	archiver             Archiver
	reportArchivePath    string
	reportArchiveSwpPath string
	openFilesMux         *sync.RWMutex
	openFiles            map[string]io.WriteCloser
}

func newReportHandler(dir, reportName, outerExt string, wcBuilder WriteCloserBuilder) (*reportHandler, error) {
	reportArchiveName := fmt.Sprintf("%s.tar%s",
		reportName,
		outerExt)
	reportArchiveSwpName := "." + reportArchiveName + ".swp"
	reportArchivePath := filepath.Join(dir, reportArchiveName)
	reportArchiveSwpPath := filepath.Join(dir, reportArchiveSwpName)

	reportTar, err := os.OpenFile(reportArchiveSwpPath, os.O_CREATE|os.O_RDWR, 0640)
	if err != nil {
		return nil, fmt.Errorf("could not create output report archive, reason: %w", err)
	}
	// reportTar is closed by the wrapping WriteCloser

	decoratedReportTar, err := wcBuilder.Build(reportTar)
	if err != nil {
		return nil, fmt.Errorf("could not initialize archive, reason: %w", err)
	}
	reportArchiver := NewTarArchiver(decoratedReportTar)

	return &reportHandler{
		archiver:             reportArchiver,
		reportArchivePath:    reportArchivePath,
		reportArchiveSwpPath: reportArchiveSwpPath,
		openFilesMux:         &sync.RWMutex{},
		openFiles:            make(map[string]io.WriteCloser),
	}, nil
}

func (h *reportHandler) CreateFile(filepath string) error {
	h.openFilesMux.Lock()
	defer h.openFilesMux.Unlock()

	filepath = sanitizePath(filepath)

	if _, exists := h.openFiles[filepath]; exists {
		return fmt.Errorf("file '%s' already opened", filepath)
	}

	file, err := h.archiver.Create(filepath)
	if err != nil {
		return err
	}
	h.openFiles[filepath] = file
	return nil
}

func (h *reportHandler) WriteFile(filepath string, data []byte) error {
	h.openFilesMux.RLock()
	defer h.openFilesMux.RUnlock()

	filepath = sanitizePath(filepath)

	file, ok := h.openFiles[filepath]
	if !ok {
		return fmt.Errorf("file '%s' has not been opened", filepath)
	}
	_, err := file.Write(data)
	return err
}

func (h *reportHandler) CloseFile(filepath string) error {
	h.openFilesMux.Lock()
	defer h.openFilesMux.Unlock()

	filepath = sanitizePath(filepath)

	file, ok := h.openFiles[filepath]
	if !ok {
		return fmt.Errorf("file '%s' has not been opened", filepath)
	}
	delete(h.openFiles, filepath)

	return file.Close()
}

func (h *reportHandler) Close() error {
	h.openFilesMux.Lock()
	defer h.openFilesMux.Unlock()

	var err error
	for _, closer := range h.openFiles {
		err = errors.NewMultiError(err, closer.Close())
	}

	h.openFiles = nil

	err = errors.NewMultiError(err, h.archiver.Close())
	err = errors.NewMultiError(err, os.Rename(h.reportArchiveSwpPath, h.reportArchivePath))
	return err
}

func removeNewlines(s string) string {
	return strings.Replace(strings.Replace(s, "\n", "", -1), "\r", "", -1)
}

func sanitizeStringForLogs(s string) string {
	return removeNewlines(s)
}

func sanitizePath(path string) string {
	return strings.Trim(filepath.Clean(removeNewlines(path)), "/")
}
