package app

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/fkie-cad/yapscan/version"

	"github.com/fkie-cad/yapscan"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var DefaultNumberOfFilescanThreads int

func init() {
	DefaultNumberOfFilescanThreads = runtime.GOMAXPROCS(0) / 2
	if DefaultNumberOfFilescanThreads < 1 {
		DefaultNumberOfFilescanThreads = 1
	}
}

func initAppAction(c *cli.Context) error {
	lvl, err := logrus.ParseLevel(c.String("log-level"))
	if err != nil {
		return err
	}
	logrus.SetLevel(lvl)
	switch c.String("log-path") {
	case "-":
		logrus.SetOutput(os.Stdout)
	case "--":
		logrus.SetOutput(os.Stderr)
	default:
		logfile, err := os.OpenFile(c.String("log-path"), os.O_WRONLY|os.O_CREATE|os.O_APPEND|os.O_SYNC, 0666)
		if err != nil {
			return fmt.Errorf("could not open logfile for writing, reason: %w", err)
		}
		logrus.SetOutput(logfile)
		logrus.RegisterExitHandler(func() {
			logfile.Close()
		})
	}
	logrus.WithField("arguments", os.Args).Debug("Program started.")
	return nil
}

func filterFromArgs(c *cli.Context) (yapscan.MemorySegmentFilter, error) {
	var err error
	i := 0

	filters := make([]yapscan.MemorySegmentFilter, 9)

	filters[i], err = BuildFilterPermissions(c.String("filter-permissions"))
	if err != nil {
		return nil, fmt.Errorf("invalid flag \"--filter-permissions\", reason: %w", err)
	}
	i += 1
	filters[i], err = BuildFilterPermissionsExact(c.StringSlice("filter-permissions-exact"))
	if err != nil {
		return nil, fmt.Errorf("invalid flag \"--filter-permissions-exact\", reason: %w", err)
	}
	i += 1
	filters[i], err = BuildFilterType(c.StringSlice("filter-type"))
	if err != nil {
		return nil, fmt.Errorf("invalid flag \"--filter-type\", reason: %w", err)
	}
	i += 1
	filters[i], err = BuildFilterState(c.StringSlice("filter-state"))
	if err != nil {
		return nil, fmt.Errorf("invalid flag \"--filter-state\", reason: %w", err)
	}
	i += 1
	filters[i], err = BuildFilterSizeMax(c.String("filter-size-max"))
	if err != nil {
		return nil, fmt.Errorf("invalid flag \"--filter-size-max\", reason: %w", err)
	}
	i += 1
	filters[i], err = BuildFilterSizeMin(c.String("filter-size-min"))
	if err != nil {
		return nil, fmt.Errorf("invalid flag \"--filter-size-min\", reason: %w", err)
	}
	i += 1
	filters[i], err = BuildRSSRatioMin(c.String("filter-rss-ratio-min"))
	if err != nil {
		return nil, fmt.Errorf("invalid flag \"--filter-rss-ratio-min\", reason: %w", err)
	}
	i += 1

	return yapscan.NewAndFilter(filters...), nil
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

func MakeApp() *cli.App {
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
			Value:   cli.NewStringSlice("commit"),
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
		&cli.StringFlag{
			Name:    "filter-rss-ratio-min",
			Aliases: []string{"f-rss-min"},
			Usage:   "minimum RSS/Size ratio of memory segments to eb considered",
		},
	}

	app := &cli.App{
		Name:        "yapscan",
		HelpName:    "yapscan",
		Description: "A yara based scanner for files and process memory with some extras.",
		Version:     fmt.Sprintf("%s (%s)", version.YapscanVersion.String(), runtime.Version()),
		Writer:      os.Stdout,
		ErrWriter:   os.Stderr,
		Authors: []*cli.Author{
			{
				Name:  "Luca Corbatto",
				Email: "luca.corbatto@fkie.fraunhofer.de",
			},
			{
				Name: "Fraunhofer FKIE",
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
			{
				Name:    "list-processes",
				Aliases: []string{"ps", "lsproc"},
				Usage:   "lists all running processes",
				Action:  listProcesses,
				Flags: append([]cli.Flag{
					&cli.BoolFlag{
						Name:    "verbose",
						Aliases: []string{"v"},
						Usage:   "output errors if any are encountered",
					},
				}, segmentFilterFlags...),
			},
			{
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
			{
				Name:      "dump",
				Usage:     "dumps memory of a process",
				Action:    dumpMemory,
				ArgsUsage: "<pid> [address_of_section]",
				Flags: append(append([]cli.Flag{
					&cli.IntFlag{
						Name:    "contiguous",
						Aliases: []string{"c"},
						Usage:   "also dump the following <value> contiguous sections, -1 for all contiguous sections, only relevant if [address_of_section] is given",
					},
					&cli.BoolFlag{
						Name:    "raw",
						Aliases: []string{"r"},
						Usage:   "dump the raw memory as opposed to a hex view of the memory",
						Value:   false,
					},
					&cli.BoolFlag{
						Name:  "store",
						Usage: "don't output, but store raw matching segments in --storage-dir",
						Value: false,
					},
					&cli.StringFlag{
						Name:    "storage-dir",
						Aliases: []string{"d"},
						Usage:   "directory for stored segments, ignored unless --store is given",
						Value:   ".",
					},
				}, suspendFlags...), segmentFilterFlags...),
			},
			{
				Name:      "scan",
				Usage:     "scans processes or paths with yara rules",
				Action:    scan,
				ArgsUsage: "[pid/path...]",
				Flags: append(append([]cli.Flag{
					&cli.StringFlag{
						Name:     "rules",
						Aliases:  []string{"r", "C"},
						Usage:    "path to yara rules file or directory, if it's a file it can be a yara rules file or a zip containing a rules file encrypted with password \"infected\"",
						Required: true,
					},
					&cli.BoolFlag{
						Name:    "rules-recurse",
						Aliases: []string{"recurse-rules", "rr"},
						Usage:   "if --rules specifies a directory, compile rules recursively",
						Value:   false,
					},
					// TODO: Currently *always* recurses!
					//&cli.BoolFlag{
					//	Name:    "recurse",
					//	Aliases: []string{"R"},
					//	Usage:   "recursive scan of path",
					//	Value:   false,
					//},
					&cli.BoolFlag{
						Name:    "all-processes",
						Aliases: []string{"all-p"},
						Usage:   "scan all running processes",
						Value:   false,
					},
					&cli.BoolFlag{
						Name:    "all-drives",
						Aliases: []string{"all-d"},
						Usage:   "scan all files in all local drives, implies --recurse",
						Value:   false,
					},
					&cli.BoolFlag{
						Name:    "all-shares",
						Aliases: []string{"all-s"},
						Usage:   "scan all files in all mounted net-shares, implies --recurse",
						Value:   false,
					},
					&cli.StringSliceFlag{
						Name:    "file-extensions",
						Aliases: []string{"e"},
						Usage:   "list of file extensions to scan, use special extension \"-\" as no extension, use --file-extensions \"\" to allow any",
						Value:   cli.NewStringSlice("-", "so", "exe", "dll", "sys"),
					},
					&cli.IntFlag{
						Name:    "threads",
						Aliases: []string{"t"},
						Usage:   "number of threads (goroutines) used for scanning files",
						Value:   DefaultNumberOfFilescanThreads,
					},
					&cli.BoolFlag{
						Name:  "full-report",
						Usage: "create a full report",
						Value: false,
					},
					&cli.StringFlag{
						Name:        "report-name",
						Usage:       "name of the generated report, file-extension is added automatically",
						DefaultText: "<hostname>_<utc_timestamp>",
					},
					&cli.BoolFlag{
						Name:  "scan-mapped-files",
						Usage: "when encountering memory-mapped files also scan the backing file on disk",
						Value: false,
					},
					&cli.StringFlag{
						Name:        "report-dir",
						Usage:       "the directory to which the report archive will be written",
						DefaultText: "current working directory",
					},
					&cli.StringFlag{
						Name:  "report-server",
						Usage: "the address of the server, the reports will be sent to",
					},
					&cli.StringFlag{
						Name:  "server-ca",
						Usage: "CA.pem to use when validating the server",
					},
					&cli.StringFlag{
						Name:  "client-cert",
						Usage: "certificate.pem to use for client authentication",
					},
					&cli.StringFlag{
						Name:  "client-key",
						Usage: "key.pem to use for client authentication",
					},
					&cli.BoolFlag{
						Name:  "store-dumps",
						Usage: "store dumps of memory regions that match rules, implies --full-report, the report will be encrypted with --password",
						Value: false,
					},
					&cli.StringFlag{
						Name:    "password",
						Aliases: []string{"p"},
						Usage:   "setting this will encrypt the report with the given password; ignored without --full-report",
					},
					&cli.StringFlag{
						Name:    "pgpkey",
						Aliases: []string{"k"},
						Usage:   "setting this will encrypt the report with the public key in the given file; ignored without --full-report",
					},
					&cli.BoolFlag{
						Name:  "anonymize",
						Usage: "anonymize any output, hashing any usernames, hostnames and IPs with a salt",
					},
					&cli.StringFlag{
						Name:        "salt",
						Usage:       "the salt (base64 string) to use for anonymization, ignored unless --anonmyize is provided",
						DefaultText: "random salt",
					},
					&cli.BoolFlag{
						Name:    "verbose",
						Aliases: []string{"v"},
						Usage:   "show more information about rule matches",
						Value:   false,
					},
				}, segmentFilterFlags...), suspendFlags...),
			},
			{
				Name:      "receive",
				Usage:     "starts a server receiving reports from other yapscan clients (see --report-server flag of scan command)",
				Action:    receive,
				ArgsUsage: "<listen-address>",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "report-dir",
						Usage:       "the directory to which the report archives will be written",
						DefaultText: "current working directory",
					},
					&cli.StringFlag{
						Name:    "password",
						Aliases: []string{"p"},
						Usage:   "setting this will encrypt the report with the given password; ignored without --full-report",
					},
					&cli.StringFlag{
						Name:    "pgpkey",
						Aliases: []string{"k"},
						Usage:   "setting this will encrypt the report with the public key in the given file; ignored without --full-report",
					},
					&cli.StringFlag{
						Name:  "server-cert",
						Usage: "certificate.pem to use for TLS",
					},
					&cli.StringFlag{
						Name:  "server-key",
						Usage: "key.pem to use for TLS",
					},
					&cli.StringFlag{
						Name:        "client-ca",
						Usage:       "CA.pem to use for client authentication",
						DefaultText: "no client authentication by default",
					},
					&cli.BoolFlag{
						Name:    "verbose",
						Aliases: []string{"v"},
						Usage:   "activate debug output of the http server",
					},
				},
			},
			{
				Name:      "anonymize",
				Usage:     "anonymize reports",
				Action:    anonymize,
				ArgsUsage: "<path...>",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "output-dir",
						Usage:       "the directory to which the anonymized report(s) will be written",
						DefaultText: "same directory as the input report",
					},
					&cli.StringFlag{
						Name:    "decrypt-password",
						Aliases: []string{"P"},
						Usage: "decryption password, if --decrypt-pgpkey is specified this is used as the password " +
							"for the keyring, otherwise this is used for symmetric decryption",
					},
					&cli.StringFlag{
						Name:    "decrypt-pgpkey",
						Aliases: []string{"K"},
						Usage:   "private pgp key for reading the reports",
					},
					&cli.BoolFlag{
						Name:  "decrypt",
						Usage: "permanently decrypt the reports without reencryption",
					},
					&cli.StringFlag{
						Name:    "password",
						Aliases: []string{"p"},
						Usage:   "setting this will encrypt the anonymized reports with the given password",
					},
					&cli.StringFlag{
						Name:    "pgpkey",
						Aliases: []string{"k"},
						Usage:   "setting this will encrypt the anonymized report with the public key in the given file",
					},
					&cli.StringFlag{
						Name:        "salt",
						Usage:       "the salt (base64 string) to use for anonymization",
						DefaultText: "random salt",
					},
				},
			},
			{
				Name:      "zip-rules",
				Usage:     "creates an encrypted zip containing compiled yara rules",
				Action:    zipRules,
				ArgsUsage: "<path_to_rules>",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "name of the output file, \"<path_to_rules>.zip\" by default",
					},
					&cli.BoolFlag{
						Name:    "rules-recurse",
						Aliases: []string{"recurse-rules", "rr"},
						Usage:   "if --rules specifies a directory, compile rules recursively",
						Value:   false,
					},
				},
			},
			{
				Name:      "join",
				Usage:     "joins dumps with padding",
				Action:    join,
				ArgsUsage: "<dumpfile> [dumpfiles...]",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "name of output file, by default the name is derived from the input names",
					},
					&cli.StringFlag{
						Name:  "padding",
						Usage: "the padding byte to use",
						Value: "0xCC",
					},
				},
			},
			{
				Name:    "crash-process",
				Aliases: []string{"crash"},
				Usage:   "crash a process",
				Action:  crashProcess,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "method",
						Aliases: []string{"m"},
						Usage:   "output errors if any are encountered",
						Value:   "CreateThreadOnNull",
					},
				},
			},
		},
	}

	if runtime.GOOS == "windows" {
		app.Commands = append(app.Commands,
			&cli.Command{
				Name:            "as-service",
				Usage:           "executes yapscan as a windows service",
				SkipFlagParsing: true,
				Action: func(c *cli.Context) error {
					if len(os.Args) < 2 || os.Args[1] != "as-service" {
						return cli.Exit("\"as-service\" must be the first argument", 1)
					}
					if len(os.Args) == 2 {
						return cli.Exit("not enough arguments for \"as-service\", "+
							"please provide the command to execute as a service", 1)
					}
					args := make([]string, 0, len(os.Args)-1)
					args = append(args, os.Args[0])
					args = append(args, os.Args[2:]...) // Cut out the "as-service" argument
					return asService(args)
				},
			})
	}

	return app
}
