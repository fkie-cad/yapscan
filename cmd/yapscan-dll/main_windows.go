package main

import "C"
import (
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/sirupsen/logrus"

	"github.com/urfave/cli/v2"

	"github.com/fkie-cad/yapscan/app"

	"github.com/google/shlex"
)

// #include<windows.h>
// #include<stdio.h>
//
// extern __declspec(dllexport) int start(int argc, char** argv);
// extern __declspec(dllexport) void run(HWND hwnd, HINSTANCE hinst, LPTSTR lpCmdLine, int nCmdShow);
//
// static char* arg_index(char** argv, int i) {
//     return argv[i];
// }
//
// static void prepare_console() {
//     AllocConsole();
//
//     freopen("CONIN$", "r", stdin);
//     freopen("CONOUT$", "w", stdout);
//     freopen("CONOUT$", "w", stderr);
// }
import "C"

//export start
func start(argc C.int, argv **C.char) C.int {
	args := make([]string, argc)
	for i := range args {
		args[i] = C.GoString(C.arg_index(argv, C.int(i)))
	}
	err := app.MakeApp(args).Run(args)
	if err != nil {
		fmt.Println(err)
		logrus.Error(err)
		logrus.Fatal("Aborting.")
	}
	return 0
}

//export run
func run(hWnd C.HWND, hInst C.HINSTANCE, lpCmdLine C.LPTSTR, nCmdShow C.int) {
	C.prepare_console()

	hIn, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE)
	if err == nil {
		os.Stdin = os.NewFile(uintptr(hIn), "/dev/stdin")
	}
	hOut, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err == nil {
		os.Stdout = os.NewFile(uintptr(hOut), "/dev/stdout")
	}
	hErr, err := windows.GetStdHandle(windows.STD_ERROR_HANDLE)
	if err == nil {
		os.Stderr = os.NewFile(uintptr(hErr), "/dev/stderr")
	}

	exiter := func(code int) {
		os.Stdout.Sync()
		os.Stderr.Sync()

		fmt.Printf("Yapscan exited with code: %d\n", code)
		fmt.Println("Please close this window.")

		for {
			time.Sleep(1 * time.Second)
		}
	}
	cli.OsExiter = exiter
	logrus.RegisterExitHandler(func() {
		os.Stdout.Sync()
		os.Stderr.Sync()

		fmt.Println("Yapscan has encountered a fatal error.")
		fmt.Println("Please close this window.")

		for {
			time.Sleep(1 * time.Second)
		}
	})

	str := C.GoString(lpCmdLine)
	// Slightly hacky way to avoid having to use double-backslashes in windows paths.
	str = strings.ReplaceAll(str, "\\", "\\\\")
	args, _ := shlex.Split(str)
	args = append([]string{"rundll32.exe"}, args...)

	err = app.MakeApp(args).Run(args)
	if err != nil {
		fmt.Println(err)
		logrus.Error(err)
		logrus.Fatal("Aborting.")
	}

	// Just in case
	exiter(0)
}

func main() {}
