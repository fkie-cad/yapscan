package app

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"fraunhofer/fkie/yapscan"
	"fraunhofer/fkie/yapscan/procIO"
	"io"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/dustin/go-humanize"
	"github.com/hillu/go-yara/v4"
	"github.com/sirupsen/logrus"
	"github.com/targodan/go-errors"
	"github.com/urfave/cli/v2"
)

const yaraRulesNamespace = ""

func initAppAction(c *cli.Context) (func(), error) {
	lvl, err := logrus.ParseLevel(c.String("log-level"))
	if err != nil {
		return nil, err
	}
	logrus.SetLevel(lvl)
	switch c.String("log-path") {
	case "-":
		logrus.SetOutput(os.Stdout)
	case "--":
		logrus.SetOutput(os.Stderr)
	default:
		logfile, err := os.OpenFile(c.String("log-path"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			return nil, errors.Errorf("could not open logfile for writing, reason: %w", err)
		}
		logrus.SetOutput(logfile)
		return func() {
			logfile.Close()
		}, nil
	}
	logrus.WithField("arguments", os.Args).Debug("Program started.")
	return nil, nil
}

func listProcesses(c *cli.Context) error {
	onClose, err := initAppAction(c)
	if err != nil {
		return err
	}
	if onClose != nil {
		defer onClose()
	}

	pids, err := procIO.GetRunningPIDs()
	if err != nil {
		return errors.Newf("could not enumerate PIDs, reason: %w", err)
	}

	for _, pid := range pids {
		fmt.Println(pid)
	}

	return nil
}

func filterFromArgs(c *cli.Context) (yapscan.MemorySegmentFilter, error) {
	var err error
	i := 0

	filters := make([]yapscan.MemorySegmentFilter, 8)

	filters[i], err = BuildFilterPermissions(c.String("filter-permissions"))
	if err != nil {
		return nil, errors.Errorf("invalid flag \"--filter-permissions\", reason: %w", err)
	}
	i += 1
	filters[i], err = BuildFilterPermissionsExact(c.StringSlice("filter-permissions-exact"))
	if err != nil {
		return nil, errors.Errorf("invalid flag \"--filter-permissions-exact\", reason: %w", err)
	}
	i += 1
	filters[i], err = BuildFilterType(c.StringSlice("filter-type"))
	if err != nil {
		return nil, errors.Errorf("invalid flag \"--filter-type\", reason: %w", err)
	}
	i += 1
	filters[i], err = BuildFilterState(c.StringSlice("filter-state"))
	if err != nil {
		return nil, errors.Errorf("invalid flag \"--filter-state\", reason: %w", err)
	}
	i += 1
	filters[i], err = BuildFilterSizeMax(c.String("filter-size-max"))
	if err != nil {
		return nil, errors.Errorf("invalid flag \"--filter-size-max\", reason: %w", err)
	}
	i += 1
	filters[i], err = BuildFilterSizeMin(c.String("filter-size-min"))
	if err != nil {
		return nil, errors.Errorf("invalid flag \"--filter-size-min\", reason: %w", err)
	}
	i += 1

	return yapscan.NewAndFilter(filters...), nil
}

func listMemory(c *cli.Context) error {
	onClose, err := initAppAction(c)
	if err != nil {
		return err
	}
	if onClose != nil {
		defer onClose()
	}

	if c.NArg() != 1 {
		return errors.Newf("expected exactly one argument, got %d", c.NArg())
	}
	pid_, err := strconv.ParseUint(c.Args().Get(0), 10, 64)
	if err != nil {
		return errors.Newf("\"%s\" is not a pid", c.Args().Get(0))
	}
	pid := int(pid_)

	f, err := filterFromArgs(c)
	if err != nil {
		return err
	}

	proc, err := procIO.OpenProcess(pid)
	if err != nil {
		return errors.Newf("could not open process with pid %d, reason: %w", pid, err)
	}

	segments, err := proc.MemorySegments()
	if err != nil {
		return errors.Newf("could not enumerate memory segments of process %d, reason: %w", pid, err)
	}
	for _, seg := range segments {
		fRes := f.Filter(seg)
		if !fRes.Result {
			continue
		}

		format := "%19s %8s %3s %7s %7s %s\n"

		fmt.Printf(format, procIO.FormatMemorySegmentAddress(seg), humanize.Bytes(seg.Size), seg.CurrentPermissions, seg.Type, seg.State, seg.FilePath)

		if c.Bool("list-subdivided") {
			for i, sseg := range seg.SubSegments {
				addr := procIO.FormatMemorySegmentAddress(sseg)
				if i+1 < len(seg.SubSegments) {
					addr = "├" + addr
				} else {
					addr = "└" + addr
				}

				fmt.Printf(format, addr, humanize.Bytes(sseg.Size), sseg.CurrentPermissions, sseg.Type, sseg.State, sseg.FilePath)
			}
		}
	}

	return nil
}

func dumpMemory(c *cli.Context) error {
	onClose, err := initAppAction(c)
	if err != nil {
		return err
	}
	if onClose != nil {
		defer onClose()
	}

	var dumper io.WriteCloser
	if c.Bool("raw") {
		dumper = os.Stdout
	} else {
		dumper = hex.Dumper(os.Stdout)
		defer dumper.Close()
	}

	if c.NArg() != 2 {
		return errors.Newf("expected exactly two arguments, got %d", c.NArg())
	}
	pid_, err := strconv.ParseUint(c.Args().Get(0), 10, 64)
	if err != nil {
		return errors.Newf("\"%s\" is not a pid", c.Args().Get(0))
	}
	pid := int(pid_)

	addrS := c.Args().Get(1)
	if strings.Index(addrS, "0x") == 0 {
		addrS = addrS[2:]
	}
	addr, err := strconv.ParseUint(addrS, 16, 64)
	if err != nil {
		return errors.Newf("\"%s\" is not an address", c.Args().Get(1))
	}

	proc, err := procIO.OpenProcess(pid)
	if err != nil {
		return errors.Newf("could not open process %d, reason: %w", pid, err)
	}

	segments, err := proc.MemorySegments()
	if err != nil {
		return errors.Newf("could not retrieve memory segments of process %d, reason: %w", pid, err)
	}
	readContiguous := c.Int("contiguous")
	found := false
	for i, seg := range segments {
		if seg.BaseAddress == addr {
			found = true
		}
		if found {
			rdr, err := procIO.NewMemoryReader(proc, seg)
			if err != nil {
				return errors.Newf("could not read memory of process %d at address 0x%016X, reason %w", pid, seg.BaseAddress, err)
			}
			_, err = io.Copy(dumper, rdr)
			if err != nil {
				return errors.Newf("could not read memory of process %d at address 0x%016X, reason %w", pid, seg.BaseAddress, err)
			}

			if readContiguous == 0 || (i+1 < len(segments) && segments[i+1].BaseAddress != seg.BaseAddress+seg.Size) {
				// Next segment is not contiguous
				break
			}
		}
	}
	if !found {
		errors.Newf("process %d has no memory segment starting with address 0x%016X", pid, addr)
	}
	return nil
}

func askYesNoAlways(msg string) (yes bool, always bool) {
	var validAnswer bool
	for !validAnswer {
		fmt.Print(msg)
		fmt.Print(" (y/a/N): ")
		var line string
		fmt.Scanln(&line)

		switch strings.ToLower(strings.Trim(line, " \t\r\n")) {
		case "y":
			yes = true
			validAnswer = true
		case "":
			fallthrough
		case "n":
			validAnswer = true
		case "a":
			yes = true
			always = true
			validAnswer = true
		default:
			fmt.Println("Invalid answer.")
		}
	}
	return
}

func askYesNoAlwaysNever(msg string) (yes bool, always bool, never bool) {
	var validAnswer bool
	for !validAnswer {
		fmt.Print(msg)
		fmt.Print(" (y/a/N/never): ")
		var line string
		fmt.Scanln(&line)

		switch strings.ToLower(strings.Trim(line, " \t\r\n")) {
		case "y":
			yes = true
			validAnswer = true
		case "":
			fallthrough
		case "n":
			validAnswer = true
		case "a":
			yes = true
			always = true
			validAnswer = true
		case "never":
			never = true
			validAnswer = true
		default:
			fmt.Println("Invalid answer.")
		}
	}
	return
}

func scan(c *cli.Context) error {
	onClose, err := initAppAction(c)
	if err != nil {
		return err
	}
	if onClose != nil {
		defer onClose()
	}

	f, err := filterFromArgs(c)
	if err != nil {
		return err
	}

	if c.NArg() == 0 && !c.Bool("all") {
		return errors.Newf("expected at least one argument or flag \"--all\", got zero")
	}

	var rules *yara.Rules
	{
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
		fmt.Printf("Full report will be written to \"%s\".\n", gatherRep.ZIP)
		if c.Bool("store-dumps") {
			err = gatherRep.WithFileDumpStorage("dumps")
			if err != nil {
				return errors.Errorf("could not initialize analysis reporter, reason: %w", err)
			}
			gatherRep.ZIPPassword = c.String("password")
		}
	}
	defer reporter.Close()

	err = reporter.ReportSystemInfo()
	logrus.WithError(err).Error("Could not report on system infos.")

	err = reporter.ReportRules(rules)
	logrus.WithError(err).Error("Could not report on yara rules.")

	alwaysSuspend := c.Bool("force")
	alwaysDumpWithoutSuspend := false
	neverDumpWithoutSuspend := false

	for _, pid := range pids {
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
					logrus.WithError(err).Errorf("could not suspend process %d", pid)
					continue
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
			continue
		}
		err = reporter.ConsumeScanProgress(progress)
		if err != nil {
			logrus.WithError(err).Error("an error occurred during progress report, there may be no other output")
			continue
		}
	}

	return nil
}

func RunApp(args []string) {
	suspendFlags := []cli.Flag{
		&cli.BoolFlag{
			Name:    "suspend",
			Aliases: []string{"s"},
			Usage:   "suspend the process before reading its memory",
			Value:   false,
		},
		&cli.BoolFlag{
			Name:    "force",
			Aliases: []string{"f"},
			Usage:   "don't ask before suspending a process",
			Value:   false,
		},
	}

	segmentFilterFlags := []cli.Flag{
		&cli.StringFlag{
			Name:    "filter-permissions",
			Aliases: []string{"f-perm"},
			Usage:   "only consider segments with the given permissions or more, examples: \"rw\" includes segments with rw, rc and rwx",
		},
		&cli.StringSliceFlag{
			Name:    "filter-permissions-exact",
			Aliases: []string{"f-perm-e"},
			Usage:   "comma separated list of permissions to be considered, supported permissions: r, rw, rc, rwx, rcx",
		},
		&cli.StringSliceFlag{
			Name:    "filter-type",
			Aliases: []string{"f-type"},
			Usage:   "comma separated list of considered types, supported types: image, mapped, private",
		},
		&cli.StringSliceFlag{
			Name:    "filter-state",
			Aliases: []string{"f-state"},
			Usage:   "comma separated list of considered states, supported states: free, commit, reserve",
			Value:   cli.NewStringSlice("commit", "reserve"),
		},
		&cli.StringFlag{
			Name:    "filter-size-max",
			Aliases: []string{"f-size-max"},
			Usage:   "maximum size of memory segments to be considered, can be absolute (e.g. \"1.5GB\"), percentage of total RAM (e.g. \"10%T\") or percentage of free RAM (e.g. \"10%F\")",
			Value:   "10%F",
		},
		&cli.StringFlag{
			Name:    "filter-size-min",
			Aliases: []string{"f-size-min"},
			Usage:   "minimum size of memory segments to be considered",
		},
	}

	app := &cli.App{
		Name:        "yapscan",
		HelpName:    "yapscan",
		Description: "A yara based scanner for files and process memory with some extras.",
		Version:     "0.1.0",
		Authors: []*cli.Author{
			&cli.Author{
				Name:  "Luca Corbatto",
				Email: "luca.corbatto@fkie.fraunhofer.de",
			},
		},
		EnableBashCompletion: true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "log-level",
				Aliases: []string{"l"},
				Usage:   "one of [trace, debug, info, warn, error, fatal, panic]",
				Value:   "panic",
			},
			&cli.StringFlag{
				Name:  "log-path",
				Usage: "path to the logfile, or \"-\" for stdout, or \"--\" for stderr",
				Value: "--",
			},
		},
		Commands: []*cli.Command{
			&cli.Command{
				Name:    "list-processes",
				Aliases: []string{"ps", "lsproc"},
				Usage:   "lists all running processes",
				Action:  listProcesses,
			},
			&cli.Command{
				Name:      "list-process-memory",
				Aliases:   []string{"lsmem"},
				Usage:     "lists all memory segments of a process",
				ArgsUsage: "<pid>",
				Flags: append(append([]cli.Flag{
					&cli.BoolFlag{
						Name:  "list-free",
						Usage: "also list free memory segments",
						Value: false,
					},
					&cli.BoolFlag{
						Name:  "list-subdivided",
						Usage: "list segment subdivisions as they are now, as opposed to segments as they were allocated once",
					},
				}, segmentFilterFlags...), suspendFlags...),
				Action: listMemory,
			},
			&cli.Command{
				Name:      "dump",
				Usage:     "dumps memory of a process",
				Action:    dumpMemory,
				ArgsUsage: "<pid> <address_of_section>",
				Flags: append([]cli.Flag{
					&cli.IntFlag{
						Name:    "contiguous",
						Aliases: []string{"c"},
						Usage:   "also dump the following <value> contiguous sections, -1 for all contiguous sections",
					},
					&cli.BoolFlag{
						Name:    "raw",
						Aliases: []string{"r"},
						Usage:   "dump the raw memory as opposed to a hex view of the memory",
						Value:   false,
					},
				}, suspendFlags...),
			},
			&cli.Command{
				Name:      "scan",
				Usage:     "scans processes with yara rules",
				Action:    scan,
				ArgsUsage: "[pid...]",
				Flags: append(append([]cli.Flag{
					&cli.StringFlag{
						Name:     "rules",
						Aliases:  []string{"r", "C"},
						Usage:    "path to yara rules file, can be compiled or uncompiled",
						Required: true,
					},
					&cli.BoolFlag{
						Name:  "all",
						Usage: "scan all running processes",
						Value: false,
					},
					&cli.BoolFlag{
						Name:  "full-report",
						Usage: "create a full report",
						Value: false,
					},
					&cli.BoolFlag{
						Name:  "store-dumps",
						Usage: "store dumps of memory regions that match rules, implies --full-report, the report will be encrypted with --password",
						Value: false,
					},
					&cli.StringFlag{
						Name:  "password",
						Usage: "the password of the encrypted report, ignored unless --store-dumps is set",
						Value: yapscan.DefaultZIPPassword,
					},
				}, segmentFilterFlags...), suspendFlags...),
			},
		},
	}

	err := app.Run(args)
	if err != nil {
		logrus.Fatal(err)
	}
}
