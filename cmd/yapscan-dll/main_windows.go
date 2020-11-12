package main

import "C"
import (
	"fmt"
	"os"

	"github.com/fkie-cad/yapscan/app"

	"github.com/sirupsen/logrus"

	"github.com/google/shlex"
	"github.com/urfave/cli/v2"
)

// #include<windows.h>
//
// extern __declspec(dllexport) int start(int argc, char** argv);
// extern __declspec(dllexport) void run(HWND hwnd, HINSTANCE hinst, LPTSTR lpCmdLine, int nCmdShow);
//
// static char* arg_index(char** argv, int i) {
//     return argv[i];
// }
import "C"

//export start
func start(argc C.int, argv **C.char) C.int {
	args := make([]string, argc)
	for i := range args {
		args[i] = C.GoString(C.arg_index(argv, C.int(i)))
	}
	app.RunApp(args)
	return 0
}

//export run
func run(hWnd C.HWND, hInst C.HINSTANCE, lpCmdLine C.LPTSTR, nCmdShow C.int) {
	res := C.AttachConsole(C.ATTACH_PARENT_PROCESS)
	if res == 0 {
		// Failure, but we cannot output anything.
		return
	}
	exiter := func(code int) {
		C.FreeConsole()
		os.Exit(code)
	}
	cli.OsExiter = exiter
	logrus.StandardLogger().ExitFunc = exiter

	fmt.Println()

	str := C.GoString(lpCmdLine)
	args, _ := shlex.Split(str)
	args = append([]string{"rundll32.exe"}, args...)

	app.RunApp(args)
	C.FreeConsole()
}

func main() {}
