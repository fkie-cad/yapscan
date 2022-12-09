package archiver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
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

func NewArchiverServer(outdir, outerExt string, builder WriteCloserBuilder) *ArchiverServer {
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

	return s
}

func (s *ArchiverServer) Start(addr string) error {
	s.server = &http.Server{
		Addr:    addr,
		Handler: s.router,
	}

	return s.server.ListenAndServe()
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
		return nil, fmt.Errorf("report with ID '%s' already exists", reportID)
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
		return nil, fmt.Errorf("report with ID '%s' does not exists", reportID)
	}
	return report, nil
}

func (s *ArchiverServer) getAndRemoveReport(reportID string) (*reportHandler, error) {
	s.reportsMux.Lock()
	defer s.reportsMux.Unlock()

	report, exists := s.openReports[reportID]
	if !exists {
		return nil, fmt.Errorf("report with ID '%s' does not exists", reportID)
	}
	delete(s.openReports, reportID)

	return report, nil
}

type CreateReportRequest struct {
	Name string `json:"name"`
}

func (s *ArchiverServer) createReport(c *gin.Context) {
	var req CreateReportRequest
	if err := c.ShouldBindJSON(&req); handleError(c, err) {
		return
	}

	reportID := generateReportID()
	_, err := s.registerReport(reportID, req.Name)
	if handleError(c, err) {
		return
	}

	logrus.Infof("Creating new report '%s' with ID '%s'", req.Name, reportID)

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
	logrus.Infof("Closed report with ID '%s'", c.Param("report"))
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

func sanitizePath(path string) string {
	return strings.Trim(filepath.Clean(path), "/")
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
