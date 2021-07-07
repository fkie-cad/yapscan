# yapscan ![build status](https://github.com/fkie-cad/yapscan/actions/workflows/ci.yml/badge.svg?branch=master) [![codecov](https://codecov.io/gh/fkie-cad/yapscan/branch/master/graph/badge.svg?token=Y2ANV37QH6)](https://codecov.io/gh/fkie-cad/yapscan) [![Go Report Card](https://goreportcard.com/badge/github.com/fkie-cad/yapscan)](https://goreportcard.com/report/github.com/fkie-cad/yapscan)

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
- Anonymization of reports with either a predefined, or a randomly generated salt

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
   crash-processe, crash       crash a processe
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
   --threads value, -t value                           number of threads (goroutines) used for scanning files (default: 6)
   --full-report                                       create a full report (default: false)
   --scan-mapped-files                                 when encountering memory-mapped files also scan the backing file on disk (default: false)
   --report-dir value                                  the directory to which the report archive will be written (default: current working directory)
   --store-dumps                                       store dumps of memory regions that match rules, implies --full-report, the report will be encrypted with --password (default: false)
   --password value                                    setting this will encrypt the report with the given password; ignored without --full-report
   --pgpkey value                                      setting this will encrypt the report with the public key in the given file; ignored without --full-report
   --anonymize                                         anonymize any output, hashing any usernames, hostnames and IPs with a salt (default: false)
   --salt value                                        the salt (base64 string) to use for anonymization, ignored unless --anonmyize is provided (default: random salt)
   --verbose, -v                                       show more information about rule matches (default: false)
   --filter-permissions value, --f-perm value          only consider segments with the given permissions or more, examples: "rw" includes segments with rw, rc and rwx
   --filter-permissions-exact value, --f-perm-e value  comma separated list of permissions to be considered, supported permissions: r, rw, rc, rwx, rcx
   --filter-type value, --f-type value                 comma separated list of considered types, supported types: image, mapped, private
   --filter-state value, --f-state value               comma separated list of considered states, supported states: free, commit, reserve (default: "commit")
   --filter-size-max value, --f-size-max value         maximum size of memory segments to be considered, can be absolute (e.g. "1.5GB"), percentage of total RAM (e.g. "10%T") or percentage of free RAM (e.g. "10%F") (default: "10%F")
   --filter-size-min value, --f-size-min value         minimum size of memory segments to be considered
   --filter-rss-ratio-min value, --f-rss-min value     minimum RSS/Size ratio of memory segments to eb considered
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

To build **natively on Linux**, for Linux you need install Go and the yara library.
Once you have installed the dependencies it's as easy as:

```bash
# Install Golang and libyara
git clone https://github.com/fkie-cad/yapscan
cd yapscan/cmd/yapscan
go build
```

If you want to build on Linux for Windows, all you need installed is docker.

```bash
# Install docker
git clone https://github.com/fkie-cad/yapscan
cd yapscan/cicd/
./crossBuildForWindows.sh
```

The resulting binaries will be placed in `cicd/build/`.

Building **natively on Windows**, using MSYS2 follow these instructions

1. Install Go
2. Install MSYS2 and follow the first steps on [the MSYS2 Website] of updating via pacman.
3. Install build dependencies `pacman --needed -S base-devel git autoconf automake libtool mingw-w64-{x86_64,i686}-{gcc,make,pkgconf}`
4. Open PowerShell in the `cicd/` directory and execute `.\buildOnWindows.ps1 -MsysPath <msys_path> -BuildDeps`
   where `<msys_path>` is the install directory for MSYS2, default is `C:\msys64`.
   **NOTE:** You'll have to press `Enter` on the MSYS window, once the dependencies are finished.
5. Enjoy the built files in `cicd/build/`

If you want to run tests on Windows, you have to run `.\cicd\buildOnWindows.ps1 -BuildDeps` only once.
Then you open PowerShell and execute `.\cicd\enableMingw.ps1 -MsysPath <msys_path>` to set the appropriate environment variables.
Now it's as easy as `go test -tags yara_static ./...`.
The `-tags yara_static` is necessary if you use the build scripts, as they do not install any windows DLLs but only the static libraries.

**NOTE:** You might get inexplicable failures with `-race` on Windows.
According to the [golang release notes for 1.14](https://golang.org/doc/go1.14#compiler), the new pointer arithmetic checks are somewhat overzealous on Windows.
In Golang v1.15 it seems this may not have been fixed, but the checks are enabled automatically.
You can deactivate them like this `go test -tags yara_static -race -gcflags=all=-d=checkptr=0 ./...`.

You don't have to rely on the powershell/bash scripts, but they are intended to make things as easy as possible at the cost of control over the compilation.
If you want more control, take a look at the scripts use and modify them or execute the commands individually.
The scripts perform the following tasks.

1. Start "MSYS2 MinGW 64-bit"
    1. Download OpenSSL from github
    2. Static-Build OpenSSL and install the development files
    3. Download libyara from github
    4. Static-Build libyara and install it
2. Set some environment variables in powershell, to allow the use of the mingw toolchain
3. Call the `go build` command with the appropriate build tag for static builds

Thanks to [@hillu] (author of [go-yara]), for pointing me in the right direction for building natively on windows.
See #7 and the links therein if you want some more details.

[the MSYS2 Website]: https://www.msys2.org/
[@hillu]: https://github.com/hillu/
[go-yara]: https://github.com/hillu/go-yara/