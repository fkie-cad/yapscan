package app

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/fkie-cad/yapscan/system"

	"github.com/fkie-cad/yapscan"
	"github.com/fkie-cad/yapscan/fileio"
	"github.com/fkie-cad/yapscan/output"
	"github.com/fkie-cad/yapscan/procio"

	"github.com/sirupsen/logrus"
	"github.com/targodan/go-errors"
	"github.com/urfave/cli/v2"
)

const filenameDateFormat = "2006-01-02_15-04-05"
const memoryScanInterval = 500 * time.Millisecond

func scan(c *cli.Context) error {
	err := initAppAction(c)
	if err != nil {
		return err
	}

	f, err := filterFromArgs(c)
	if err != nil {
		return err
	}

	fmt.Printf("Filters: %s\n\n", f.Description())
	logrus.Infof("Filters: %s", f.Description())

	if c.NArg() == 0 && !c.Bool("all-processes") && !c.Bool("all-drives") && !c.Bool("all-shares") {
		return errors.Newf("expected at least one argument, or one of the flags \"--all-processes\", \"--all-drives\", \"--all-shares\", got zero")
	}

	rules, err := yapscan.LoadYaraRules(c.String("rules"), c.Bool("rules-recurse"))
	if err != nil {
		return err
	}

	yaraScanner, err := yapscan.NewYaraScanner(rules)
	if err != nil {
		return errors.Newf("could not initialize yara scanner, reason: %w", err)
	}

	scannerStats := yaraScanner.Statistics()
	scannerStats.StartMemoryProfiler(context.Background(), memoryScanInterval)

	var pids []int
	var paths []string
	if c.NArg() > 0 {
		for i := 0; i < c.NArg(); i += 1 {
			arg := c.Args().Get(i)

			pid, err := strconv.Atoi(arg)
			if err == nil {
				// is pid
				pids = append(pids, pid)
			} else {
				// is path
				paths = append(paths, arg)
			}
		}
	}

	if c.Bool("all-processes") {
		pids, err = procio.GetRunningPIDs()
		if err != nil {
			return errors.Newf("could not enumerate PIDs, reason: %w", err)
		}
	}

	if c.Bool("all-drives") {
		// TODO: Expose the drive types to flags
		drives, err := fileio.Enumerate(fileio.DriveTypeFixed | fileio.DriveTypeRemovable)
		if err != nil {
			return fmt.Errorf("could not enumerate local drives, reason: %w", err)
		}
		paths = append(paths, drives...)
	}

	if c.Bool("all-shares") {
		// TODO: Expose the drive types to flags
		drives, err := fileio.Enumerate(fileio.DriveTypeRemote)
		if err != nil {
			return fmt.Errorf("could not enumerate net-shares, reason: %w", err)
		}
		paths = append(paths, drives...)
	}

	var anonymizer *output.Anonymizer

	var nonEmptyFilter output.Filter = &output.NoEmptyScansFilter{}
	var progressFilter output.Filter = &output.NOPFilter{}
	var analysisFilter output.Filter = nonEmptyFilter

	if c.Bool("anonymize") {
		var salt []byte
		base64Salt := c.String("salt")
		if base64Salt != "" {
			salt, err = base64.StdEncoding.DecodeString(base64Salt)
			if err != nil {
				return fmt.Errorf("could not decode given salt, reason: %w", err)
			}
		}

		var anonFilter *output.AnonymizingFilter
		if salt != nil {
			anonFilter = output.NewAnonymizingFilter(salt)
		} else {
			anonFilter, err = output.NewAnonymizingFilterWithRandomSalt(64)
			if err != nil {
				return fmt.Errorf("could not generate salt, reason: %w", err)
			}
		}
		anonymizer = anonFilter.Anonymizer

		progressFilter = anonFilter
		analysisFilter = nonEmptyFilter.Chain(anonFilter)
	}

	var reporter output.Reporter = &output.FilteringReporter{
		Reporter: output.NewProgressReporter(os.Stdout, output.NewPrettyFormatter(c.Bool("verbose"))),
		Filter:   progressFilter,
	}
	if c.Bool("full-report") || c.Bool("store-dumps") {
		wcBuilder := output.NewWriteCloserBuilder()
		if c.String("password") != "" && c.String("pgpkey") != "" {
			return fmt.Errorf("cannot encrypt with both pgp key and a password")
		}
		if c.String("password") != "" {
			wcBuilder.Append(output.PGPSymmetricEncryptionDecorator(c.String("password"), true))
		}
		if c.String("pgpkey") != "" {
			ring, err := output.ReadKeyRing(c.String("pgpkey"))
			if err != nil {
				return fmt.Errorf("could not read specified public pgp key, reason: %w", err)
			}
			wcBuilder.Append(output.PGPEncryptionDecorator(ring, true))
		}
		wcBuilder.Append(output.ZSTDCompressionDecorator())

		hostname, err := os.Hostname()
		if err != nil {
			logrus.WithError(err).Warn("Could not determine hostname.")
			h := md5.New()
			binary.Write(h, binary.LittleEndian, rand.Int())
			binary.Write(h, binary.LittleEndian, rand.Int())
			hostname = hex.EncodeToString(h.Sum(nil))
		}
		if anonymizer != nil {
			hostname = anonymizer.Anonymize(hostname)
		}

		reportArchivePath := fmt.Sprintf("%s_%s.tar%s",
			hostname,
			time.Now().UTC().Format(filenameDateFormat),
			wcBuilder.SuggestedFileExtension())
		if c.String("report-dir") != "" {
			reportArchivePath = filepath.Join(c.String("report-dir"), reportArchivePath)
		}
		reportTar, err := os.OpenFile(reportArchivePath, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return fmt.Errorf("could not create output report archive, reason: %w", err)
		}
		// reportTar is closed by the wrapping WriteCloser

		decoratedReportTar, err := wcBuilder.Build(reportTar)
		if err != nil {
			return fmt.Errorf("could not initialize archive, reason: %w", err)
		}
		reportArchiver := output.NewTarArchiver(decoratedReportTar)

		repFac := output.NewAnalysisReporterFactory(reportArchiver).
			AutoCloseArchiver().
			WithFilenamePrefix(hostname + "/")

		fmt.Printf("Full report will be written to \"%s\".\n", reportArchivePath)

		if c.Bool("store-dumps") {
			dumpArchivePath := fmt.Sprintf("%s_%s_dumps.tar%s",
				hostname,
				time.Now().UTC().Format(filenameDateFormat),
				wcBuilder.SuggestedFileExtension())
			if c.String("report-dir") != "" {
				dumpArchivePath = filepath.Join(c.String("report-dir"), dumpArchivePath)
			}
			dumpTar, err := os.OpenFile(dumpArchivePath, os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				return fmt.Errorf("could not create output dump archive, reason: %w", err)
			}
			// dumpTar is closed by the wrapping WriteCloser

			decoratedDumpTar, err := wcBuilder.Build(dumpTar)
			if err != nil {
				return fmt.Errorf("could not initialize archive, reason: %w", err)
			}
			dumpArchiver := output.NewTarArchiver(decoratedDumpTar)

			ds := output.NewArchiveDumpStorage(dumpArchiver)
			repFac.WithDumpStorage(ds)

			fmt.Printf("Dumps will be written to \"%s\".\n", dumpArchivePath)
		}
		reporter = &output.MultiReporter{
			Reporters: []output.Reporter{
				reporter,
				&output.FilteringReporter{
					Reporter: repFac.Build(),
					Filter:   analysisFilter,
				},
			},
		}
	}

	defer func() {
		err := reporter.Close()
		if err != nil {
			fmt.Println(err)
			logrus.WithError(err).Error("Error closing reporter.")
		}
	}()

	info, err := system.GetInfo()
	if err != nil {
		logrus.WithError(err).Warn("Could not determine complete system info.")
	}
	err = reporter.ReportSystemInfo(info)
	if err != nil {
		logrus.WithError(err).Error("Could not report on system infos.")
	}

	alwaysSuspend := c.Bool("force")
	alwaysDumpWithoutSuspend := false
	neverDumpWithoutSuspend := false

	memScanChan := make(chan *yapscan.MemoryScanProgress)
	memScanConsumerDone := make(chan interface{})
	go func() {
		defer func() {
			memScanConsumerDone <- nil
			close(memScanConsumerDone)
		}()

		err = reporter.ConsumeMemoryScanProgress(memScanChan)
		if err != nil {
			logrus.WithError(err).Error("an error occurred during progress report, there may be no other output")
			return
		}
	}()

	encounteredMappedFiles := make(map[string]interface{}, 0)

	for _, pid := range pids {
		func() {
			if pid == os.Getpid() {
				// Don't scan yourself as that will cause unwanted matches.
				return
			}

			proc, err := procio.OpenProcess(pid)
			if err != nil {
				logrus.WithError(err).Errorf("could not open process %d for scanning", pid)
				return
			}
			defer func() {
				if err := proc.Close(); err != nil {
					logrus.Error(err)
				}
			}()

			resume := func() {}
			if c.Bool("suspend") {
				var suspend bool
				if alwaysSuspend {
					suspend = true
				} else {
					suspend, alwaysSuspend = askYesNoAlways(fmt.Sprintf("Suspend process %d?", pid))
					if !suspend && !alwaysDumpWithoutSuspend && !neverDumpWithoutSuspend {
						var dump bool
						dump, alwaysDumpWithoutSuspend, neverDumpWithoutSuspend = askYesNoAlwaysNever("Scan anyway?")
						if !dump {
							return
						}
					}
				}

				if suspend {
					err = proc.Suspend()
					if err != nil {
						fmt.Println("Could not suspend process: ", err)
						logrus.WithError(err).Errorf("could not suspend process %d", pid)
						return
					}
					resume = func() {
						err := proc.Resume()
						if err != nil {
							fmt.Println("Could not resume process: ", err)
							logrus.WithError(err).Errorf("could not resume process %d", pid)
						}
					}
				} else {
					if neverDumpWithoutSuspend {
						return
					}
				}
			}

			scanner := yapscan.NewProcessScanner(proc, f, yaraScanner)
			scannerStats.IncrementNumberOfProcessesScanned()

			progress, err := scanner.Scan()
			if err != nil {
				logrus.WithError(err).Errorf("an error occurred during scanning of process %d", pid)
				resume()
				return
			}
			for prog := range progress {
				memScanChan <- prog
			}
			resume()

			for _, f := range scanner.EncounteredMemoryMappedFiles() {
				encounteredMappedFiles[f] = nil
			}
		}()
	}
	close(memScanChan)
	<-memScanConsumerDone

	fileExtensions := c.StringSlice("file-extensions")
	if len(fileExtensions) == 1 && fileExtensions[0] == "" {
		fileExtensions = fileExtensions[1:]
	}
	for i := range fileExtensions {
		if fileExtensions[i] == "-" {
			fileExtensions[i] = ""
		}
	}

	if len(paths) > 0 {
		fmt.Println("Going to scan the following paths:")
	}

	iteratorCtx := context.Background()
	var pathIterator fileio.Iterator

	if c.Bool("scan-mapped-files") && len(encounteredMappedFiles) > 0 {
		encounteredMappedFilesList := make([]string, 0, len(encounteredMappedFiles))
		for f, _ := range encounteredMappedFiles {
			encounteredMappedFilesList = append(encounteredMappedFilesList, f)
		}
		pathIterator = fileio.IterateFileList(encounteredMappedFilesList)
	}

	for _, path := range paths {
		pIt, err := fileio.IteratePath(iteratorCtx, path, fileExtensions)
		if err != nil {
			fmt.Printf("- %s ERROR: could not intialize scanner for path, reason: %v", path, err)
			logrus.WithError(err).Errorf("Could not initialize scanner for path \"%s\".", path)
			continue
		}
		pathIterator = fileio.Concurrent(pathIterator, pIt)
		fmt.Printf("- %s\n", path)
	}

	if pathIterator != nil {
		defer pathIterator.Close()

		fsScanner := fileio.NewFSScanner(yaraScanner)
		fsScanner.NGoroutines = c.Int("threads")

		progress, _ := fsScanner.Scan(pathIterator)
		err = reporter.ConsumeFSScanProgress(progress)
		if err != nil {
			logrus.WithError(err).Error("an error occurred during progress report, there may be no other output")
		}
	}

	scannerStats.Finalize()
	err = reporter.ReportScanningStatistics(scannerStats)
	if err != nil {
		logrus.WithError(err).Error("an error occurred during reporting statistics")
	}

	return nil
}
