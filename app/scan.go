package app

import (
	"context"
	"fmt"
	"fraunhofer/fkie/yapscan"
	"fraunhofer/fkie/yapscan/fileIO"
	"fraunhofer/fkie/yapscan/output"
	"fraunhofer/fkie/yapscan/procIO"
	"os"
	"path"
	"strconv"

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
		pids, err = procIO.GetRunningPIDs()
		if err != nil {
			return errors.Newf("could not enumerate PIDs, reason: %w", err)
		}
	}

	if c.Bool("all-drives") {
		// TODO: Expose the drive types to flags
		drives, err := fileIO.Enumerate(fileIO.DriveTypeFixed | fileIO.DriveTypeRemovable)
		if err != nil {
			return fmt.Errorf("could not enumerate local drives, reason: %w", err)
		}
		paths = append(paths, drives...)
	}

	if c.Bool("all-shares") {
		// TODO: Expose the drive types to flags
		drives, err := fileIO.Enumerate(fileIO.DriveTypeRemote)
		if err != nil {
			return fmt.Errorf("could not enumerate net-shares, reason: %w", err)
		}
		paths = append(paths, drives...)
	}

	reporter := output.NewProgressReporter(os.Stdout, output.NewPrettyFormatter())
	if c.Bool("full-report") || c.Bool("store-dumps") {
		tmpDir := path.Join(os.TempDir(), "yapscan")
		fmt.Println("Full report temp dir: ", tmpDir)
		logrus.Debug("Full report temp dir: ", tmpDir)
		gatherRep, err := output.NewGatheredAnalysisReporter(tmpDir)
		if err != nil {
			return errors.Errorf("could not initialize analysis reporter, reason: %w", err)
		}
		gatherRep.ZIP = gatherRep.SuggestZIPName()
		gatherRep.DeleteAfterZipping = !c.Bool("keep")
		fmt.Printf("Full report will be written to \"%s\".\n", gatherRep.ZIP)
		if c.Bool("store-dumps") {
			err = gatherRep.WithFileDumpStorage("dumps")
			if err != nil {
				return errors.Errorf("could not initialize analysis reporter, reason: %w", err)
			}
			gatherRep.ZIPPassword = c.String("password")
		}
		reporter = &output.MultiReporter{
			Reporters: []output.Reporter{
				reporter,
				gatherRep,
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

		proc, err := procIO.OpenProcess(pid)
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
	var pathIterator fileIO.Iterator
	for _, path := range paths {
		fmt.Printf("- %s\n", path)

		pIt, err := fileIO.IteratePath(path, fileExtensions, iteratorCtx)
		if err != nil {
			return fmt.Errorf("could not initialize filesystem iterator for path \"%s\", reason: %w", path, err)
		}
		pathIterator = fileIO.Concurrent(pathIterator, pIt)
	}

	if pathIterator != nil {
		defer pathIterator.Close()

		fsScanner := fileIO.NewFSScanner(yaraScanner)
		fsScanner.NGoroutines = c.Int("threads")

		progress, _ := fsScanner.Scan(pathIterator)
		err = reporter.ConsumeFSScanProgress(progress)
		if err != nil {
			logrus.WithError(err).Error("an error occurred during progress report, there may be no other output")
		}
	}

	return nil
}
