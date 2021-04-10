package app

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/fkie-cad/yapscan"
	"github.com/fkie-cad/yapscan/fileio"
	"github.com/fkie-cad/yapscan/output"
	"github.com/fkie-cad/yapscan/procio"

	"github.com/sirupsen/logrus"
	"github.com/targodan/go-errors"
	"github.com/urfave/cli/v2"
)

func scan(c *cli.Context) error {
	err := initAppAction(c)
	if err != nil {
		return err
	}

	f, err := filterFromArgs(c)
	if err != nil {
		return err
	}

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

	var archiverCtx context.Context
	var archiverDone chan interface{}
	var reportCloser func()

	reporter := output.NewProgressReporter(os.Stdout, output.NewPrettyFormatter())
	if c.Bool("full-report") || c.Bool("store-dumps") {
		tmpDir := path.Join(os.TempDir(), "yapscan")
		fmt.Println("Full report temp dir: ", tmpDir)
		logrus.Debug("Full report temp dir: ", tmpDir)

		analRep := output.NewInMemoryAnalysisReporter()
		if c.String("password") != "" {
			analRep.WithOutputDecorator(output.PGPSymmetricEncryptionDecorator(c.String("password")))
		}
		analRep.WithOutputDecorator(output.ZSTDCompressionDecorator())

		hostname, err := os.Hostname()
		if err != nil {
			logrus.WithError(err).Warn("Could not determine hostname.")
			h := md5.New()
			binary.Write(h, binary.LittleEndian, rand.Int())
			binary.Write(h, binary.LittleEndian, rand.Int())
			hostname = hex.EncodeToString(h.Sum(nil))
		}

		archivePath := fmt.Sprintf("%s_%s.tar", hostname, time.Now().Format("2006-01-02_15-04-05"))
		tar, err := os.OpenFile(archivePath, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return fmt.Errorf("could not create output archive, reason: %w", err)
		}
		archiver, err := analRep.WithArchiver(output.NewTarArchiver(tar), hostname+"/")
		if err != nil {
			return fmt.Errorf("could not initialize output archiver, reason: %w", err)
		}
		defer analRep.Close()
		defer archiver.Close()

		// This needs to be called manually because otherwise the archiver.Wait will never resolve
		reportCloser = func() {
			err := analRep.Close()
			if err != nil {
				logrus.WithError(err).Warn("Closing report errored.")
			}
		}

		archiverCtx = context.Background()
		archiverDone = make(chan interface{})
		go func() {
			err = archiver.Wait(archiverCtx)
			if err != nil {
				logrus.WithError(err).Warn("There have been errors during archiving.")
			}
			archiverDone <- nil
		}()

		fmt.Printf("Full report will be written to \"%s\".\n", archivePath)

		//gatherRep.DeleteAfterZipping = !c.Bool("keep")
		//if c.Bool("store-dumps") {
		//	ds, err := output.NewFileDumpStorage(filepath.Join(gatherRep.Directory(), "dumps"))
		//	if err != nil {
		//		return fmt.Errorf("could not initialize dump storage reporter, reason: %w", err)
		//	}
		//	gatherRep.WithDumpStorage(ds)
		//	gatherRep.ZIPPassword = c.String("password")
		//}
		reporter = &output.MultiReporter{
			Reporters: []output.Reporter{
				reporter,
				analRep,
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

	err = reporter.ReportSystemInfo()
	if err != nil {
		logrus.WithError(err).Error("Could not report on system infos.")
	}

	err = reporter.ReportRules(rules)
	if err != nil {
		logrus.WithError(err).Error("Could not report on yara rules.")
	}

	alwaysSuspend := c.Bool("force")
	alwaysDumpWithoutSuspend := false
	neverDumpWithoutSuspend := false

	for _, pid := range pids {
		if pid == os.Getpid() {
			// Don't scan yourself as that will cause unwanted matches.
			continue
		}

		proc, err := procio.OpenProcess(pid)
		if err != nil {
			logrus.WithError(err).Errorf("could not open process %d for scanning", pid)
			continue
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
						continue
					}
				}
			}

			if suspend {
				err = proc.Suspend()
				if err != nil {
					fmt.Println("Could not suspend process: ", err)
					logrus.WithError(err).Errorf("could not suspend process %d", pid)
					continue
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
					continue
				}
			}
		}

		scanner := yapscan.NewProcessScanner(proc, f, yaraScanner)

		progress, err := scanner.Scan()
		if err != nil {
			logrus.WithError(err).Errorf("an error occurred during scanning of process %d", pid)
			resume()
			continue
		}
		err = reporter.ConsumeMemoryScanProgress(progress)
		if err != nil {
			logrus.WithError(err).Error("an error occurred during progress report, there may be no other output")
			resume()
			continue
		}
		resume()
	}

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

	// Wait for archiver if necessary
	if reportCloser != nil {
		reportCloser()
		<-archiverDone
	}

	return nil
}
