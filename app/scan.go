package app

import (
	"bytes"
	"fmt"
	"fraunhofer/fkie/yapscan"
	"fraunhofer/fkie/yapscan/procIO"
	"io"
	"os"
	"path"
	"strconv"

	"github.com/hillu/go-yara/v4"
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

	if c.NArg() == 0 && !c.Bool("all") {
		return errors.Newf("expected at least one argument or flag \"--all\", got zero")
	}

	var rules *yara.Rules
	err = func() error {
		rulesFile, err := os.OpenFile(c.String("rules"), os.O_RDONLY, 0644)
		if err != nil {
			return errors.Newf("could not open rules file, reason: %w", err)
		}
		defer rulesFile.Close()

		buff := make([]byte, 4)
		_, err = io.ReadFull(rulesFile, buff)
		if err != nil {
			return errors.Newf("could not read rules file, reason: %w", err)
		}
		rulesFile.Seek(0, io.SeekStart)

		if bytes.Equal(buff, []byte("YARA")) {
			logrus.Debug("Yara rules file contains compiled rules.")

			rules, err = yara.ReadRules(rulesFile)
			if err != nil {
				return errors.Newf("could not read rules file, reason: %w", err)
			}
		} else {
			logrus.Debug("Yara rules file needs to be compiled.")

			compiler, err := yara.NewCompiler()
			if err != nil {
				return errors.Newf("could not create yara compiler, reason: %w", err)
			}
			err = compiler.AddFile(rulesFile, yaraRulesNamespace)
			if err != nil {
				return errors.Newf("could not compile yara rules, reason: %w", err)
			}

			rules, err = compiler.GetRules()
			if err != nil {
				return errors.Newf("could not compile yara rules, reason: %w", err)
			}
		}
		return nil
	}()
	if err != nil {
		return err
	}

	yaraScanner, err := yapscan.NewYaraMemoryScanner(rules)
	if err != nil {
		return errors.Newf("could not initialize yara scanner, reason: %w", err)
	}

	var pids []int
	if c.Bool("all") {
		pids, err = procIO.GetRunningPIDs()
		if err != nil {
			return errors.Newf("could not enumerate PIDs, reason: %w", err)
		}
	} else {
		pids = make([]int, c.NArg())
		for i := 0; i < c.NArg(); i += 1 {
			pids[i], err = strconv.Atoi(c.Args().Get(i))
			if err != nil {
				return errors.Newf("argument \"%s\" is not a pid: %w", c.Args().Get(i), err)
			}
		}
	}

	reporter := yapscan.NewProgressReporter(os.Stdout, yapscan.NewPrettyFormatter())
	if c.Bool("full-report") || c.Bool("store-dumps") {
		tmpDir := path.Join(os.TempDir(), "yapscan")
		fmt.Println("Full report temp dir: ", tmpDir)
		logrus.Debug("Full report temp dir: ", tmpDir)
		gatherRep, err := yapscan.NewGatheredAnalysisReporter(tmpDir)
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
		reporter = &yapscan.MultiReporter{
			Reporters: []yapscan.Reporter{
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
		err = reporter.ConsumeScanProgress(progress)
		if err != nil {
			logrus.WithError(err).Error("an error occurred during progress report, there may be no other output")
			resume()
			continue
		}
		resume()
	}

	return nil
}
