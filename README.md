# yapscan [![Build Status](https://travis-ci.org/fkie-cad/yapscan.svg?branch=master)](https://travis-ci.org/fkie-cad/yapscan) [![codecov](https://codecov.io/gh/fkie-cad/yapscan/branch/master/graph/badge.svg?token=Y2ANV37QH6)](https://codecov.io/gh/fkie-cad/yapscan)

Yapscan is a **YA**ra based **P**rocess **SCAN**ner, aimed at giving more control about what to scan and giving detailed reports on matches.

## Features

You can use yapscan to selectively scan the memory of running processes as well as files in local hard drives and/or mounted shares.
The most notable differences to stock yara are (see section [Usage](#usage)),

- Supports loading yara-rules from an encrypted zip file to prevent anti-virus software from detecting rules as malicious.
- Multiple yara rules can also be loaded recursively from a directory. 
- Can suspend processes to be scanned (use with care, may crash your system).
- Allows for filtering of memory segments to be scanned based on size, type (image, mapped, private), state (commit, free, reserve), and permissions.
- Allows for easy scanning of all running processes, local drives and/or mounted shares.
- Comes with extensive reporting features to allow later analysis of efficacy of rules.
- Matched memory segments can even be automatically dumped and stored as part of the 

Other quality-of-life features include

- Statically built, dependency free exe for Windows
- Listing running processes
- Listing and dumping memory segments of a specific process
- Compiling yara rules and compressing them into an encrypted zip.
- Provides an "executable DLL" for locked down environments such as VDIs (see section [Executable DLL](#executable-dll))

Yapscan comes with support for both Windows and Linux, however Windows is the primary and most thoroughly tested target OS.

## Usage

*I'll write a proper man page soon. For now, use* `yapscan --help` and `yapscan <command> --help` for usage information.

```
COMMANDS:
   list-processes, ps, lsproc  lists all running processes
   list-process-memory, lsmem  lists all memory segments of a process
   dump                        dumps memory of a process
   scan                        scans processes or paths with yara rules
   zip-rules                   creates an encrypted zip containing compiled yara rules
   join                        joins dumps with padding
   help, h                     Shows a list of commands or help for one command
```

```
> yapscan scan --help
NAME:
   yapscan scan - scans processes or paths with yara rules

USAGE:
   yapscan scan [command options] [pid/path...]

OPTIONS:
   --rules value, -r value, -C value                   path to yara rules file or directory, if it's a file it can be a yara rules file or a zip containing a rules file encrypted with password "infected"
   --rules-recurse, --recurse-rules, --rr              if --rules specifies a directory, compile rules recursively (default: false)
   --all-processes, --all-p                            scan all running processes (default: false)
   --all-drives, --all-d                               scan all files in all local drives, implies --recurse (default: false)
   --all-shares, --all-s                               scan all files in all mounted net-shares, implies --recurse (default: false)
   --file-extensions value, -e value                   list of file extensions to scan, use special extension "-" as no extension, use --file-extensions "" to allow any (default: "-", "so", "exe", "dll", "sys")
   --threads value, -t value                           number of threads (goroutines) used for scanning files (default: 12)
   --full-report                                       create a full report (default: false)
   --store-dumps                                       store dumps of memory regions that match rules, implies --full-report, the report will be encrypted with --password (default: false)
   --keep                                              keep the temporary report directory, by default it will be deleted; ignored without --full-report (default: false)
   --password value                                    the password of the encrypted report, ignored unless --store-dumps is set (default: "infected")
   --filter-permissions value, --f-perm value          only consider segments with the given permissions or more, examples: "rw" includes segments with rw, rc and rwx
   --filter-permissions-exact value, --f-perm-e value  comma separated list of permissions to be considered, supported permissions: r, rw, rc, rwx, rcx
   --filter-type value, --f-type value                 comma separated list of considered types, supported types: image, mapped, private
   --filter-state value, --f-state value               comma separated list of considered states, supported states: free, commit, reserve (default: "commit")
   --filter-size-max value, --f-size-max value         maximum size of memory segments to be considered, can be absolute (e.g. "1.5GB"), percentage of total RAM (e.g. "10%T") or percentage of free RAM (e.g. "10%F") (default: "10%F")
   --filter-size-min value, --f-size-min value         minimum size of memory segments to be considered
   --suspend, -s                                       suspend the process before reading its memory (default: false)
   --force, -f                                         don't ask before suspending a process (default: false)
   --help, -h                                          show help (default: false)
```

Here are some additional example usages

```bash
# Create rules zip (optional)
yapscan zip-rules --output rules.zip rules.yara

# Scan a process with PID 423 with default filters
yapscan scan -r rules.zip 423
# Scan all processes with default filters
yapscan scan -r rules.zip --all-processes
# Scan all processes and all local drives with default filters
yapscan scan -r rules.zip --all-processes --all-drives
# Scan everything with default filters
yapscan scan -r rules.zip --all-processes --all-drives --all-shares

# Only scan memory segments with execute permission or more
yapscan scan -r rules.zip --filter-permissions x --all-processes
# Only scan memory segments with exactly read and execute (not write)
yapscan scan -r rules.zip --filter-permissions-exact rx --all-processes

# Enable logging, reporting and auto dumping of matched segments
yapscan --log-level debug --log-path yapscan.log scan -r rules.zip --full-report --store-dumps --all-processes
```

## Executable DLL

**The DLL built by this project is not a usual DLL, meant for importing functions from.**
Instead it acts similarly to the exe with two exported, high-level entry points:

```C
// start acts same as you would expect a main function to act.
// It assumes a terminal with stdout/stderr and stdin has already
// been allocated.
extern int start(int argc, char** argv);

// run is meant for use with rundll32.
// It opens a new console window via AllocConsole(), then parses the
// lpCmdLine to extract the arguments and calls starts yapscan
// with the extracted arguments. 
extern void run(HWND hWnd, HINSTANCE hInst, LPTSTR lpCmdLine, int nCmdShow);
```

Some environments like VDIs (Virtual Desktop Infrastructure) may prevent the execution of arbitrary exe-files but still allows for use of arbitrary DLLs.
If you gain access to a command line terminal in such an environment you can call yapscan via the built DLL like so.

```
rundll32.exe yapscan.dll,run scan -r rules.zip --all-processes
```  

**NOTE**: This feature is still experimental!
There very likely are quirks with the argument parsing. 

## State of this project

**BETA, FeatureFreeze**

Right now yapscan is in a beta period.
I am currently working on a stable 1.0 release.
This release will have a defined and documented stable API and cli interface that will remain backwards compatible for all 1.x versions.
Before releasing 1.0 I also want to have at least a reasonable amount of test-coverage.

Feel free to use and test it and open issues for any bugs you may find.
If you would like to have some additional features you can also open an issue with a feature request, but until the 1.0 release I will not be working on or merging any new features.

## Contributing

Found a bug or want a feature, but you can't code or don't have the time?
Feel free to open an issue! Please look for duplicates first.

If you want to contribute code, be it fixes or features, please open a pull request **on the develop branch** and mention any related issues.

In the rapid-development phase I have only used the master branch, but will switch very shortly to the [git-flow workflow](https://danielkummer.github.io/git-flow-cheatsheet/index.html).
This means the master branch will represent the latest stable release at any point in time and any work-in-progress is to be merged into the develop branch.

## Scanning Technique

The actual scanning is left to the yara library.
In case of file scanning, the high level yara library function `yr_rules_scan_file` is used.
This function memory-maps the given file.
Scanning process memory, on the other hand, is done on a lower level.
Yapscan copies one memory segment at a time into a buffer in its own memory and then uses `yr_rules_scan_mem` in order to scan this buffer.

## Building Yapscan

This project can only be built on Linux at this time.
To build natively on Linux, for Linux you need install Go and the yara library.
Once you have installed the dependencies it's as easy as:

```bash
# Install Golang and libyara
git clone https://github.com/fkie-cad/yapscan
cd yapscan
./prepare.sh
cd cmd/yapscan
go build
```

If you want to build on Linux for Windows, all you need installed is docker.

```bash
# Install docker
git clone https://github.com/fkie-cad/yapscan
cd yapscan
./buildForWindows.sh
```

### Why can I not build this project on Windows?

I have been unable, so far, to build libyara on Windows and marry the result to the go toolchain to create a static build.

If you have experience with cgo on Windows, it would be great if you could help out.
This is relatively important for automated testing.
