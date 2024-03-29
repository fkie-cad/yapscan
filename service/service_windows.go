package service

import (
	"fmt"
	"os"
	"strconv"

	"github.com/fkie-cad/yapscan/service/output"

	"golang.org/x/sys/windows"

	"github.com/fkie-cad/yapscan/app"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

// Built using this example: https://docs.microsoft.com/en-us/windows/win32/services/writing-a-servicemain-function

// #include <windows.h>
//
// static char* SERVICE_NAME = "yapscan";
// static SERVICE_STATUS          gSvcStatus = {0};
// static SERVICE_STATUS_HANDLE   gSvcStatusHandle = NULL;
// static HANDLE                  ghSvcStopEvent = NULL;
//
// extern void __declspec(dllexport) SvcMain(DWORD dwNumServicesArgs, LPSTR *lpServiceArgVectors);
// extern void __declspec(dllexport) SvcCtrlHandler(DWORD dwCtrl);
//
// static int startServiceDispatcher() {
//     SERVICE_TABLE_ENTRY serviceTable[] = {
//	       {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)SvcMain},
// 		   {NULL, NULL}
//     };
//     if(StartServiceCtrlDispatcher(serviceTable) == FALSE) {
//		   return 1;
//	   }
//     return 0;
// }
//
// static const char* arg_index(const char** argv, int i) {
//     return argv[i];
// }
//
// static void ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint) {
//     static DWORD dwCheckPoint = 1;
//
//     // Fill in the SERVICE_STATUS structure.
//
//     gSvcStatus.dwCurrentState = dwCurrentState;
//     gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
//     gSvcStatus.dwWaitHint = dwWaitHint;
//
//     if(dwCurrentState == SERVICE_START_PENDING)
//         gSvcStatus.dwControlsAccepted = 0;
//     else gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
//
//     if ((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED))
//         gSvcStatus.dwCheckPoint = 0;
//     else gSvcStatus.dwCheckPoint = dwCheckPoint++;
//
//     // Report the status of the service to the SCM.
//     SetServiceStatus( gSvcStatusHandle, &gSvcStatus );
// }
//
// static int init_status() {
//     gSvcStatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, SvcCtrlHandler);
//     if(!gSvcStatusHandle) {
//         return 1;
//     }
//
//     gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
//     gSvcStatus.dwServiceSpecificExitCode = 0;
//     ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
//
//	   ghSvcStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
//     if(ghSvcStopEvent == NULL) {
//	       ReportSvcStatus(SERVICE_STOPPED, GetLastError(), 0);
//         return 2;
//     }
//
//     return 0;
// }
//
// static void report_running() {
//     ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
// }
// static void report_stopped() {
//     ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
// }
import "C"

//export SvcCtrlHandler
func SvcCtrlHandler(dwCtrl C.DWORD) {
	// We could handle commands from the service manager, but let's just not...
}

//export SvcMain
func SvcMain(dwNumServicesArgs C.DWORD, lpServiceArgVectors **C.char) {
	if C.init_status() != C.int(0) {
		return
	}

	out, _ := os.OpenFile("C:\\yapscanOut.txt", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
	defer out.Close()

	args := make([]string, dwNumServicesArgs)
	for i := range args {
		args[i] = C.GoString(C.arg_index(lpServiceArgVectors, C.int(i)))
	}
	fmt.Fprintf(out, "ARGS: %v\r\n", args)

	var outputProxyClient *output.OutputProxyClient
	if args[1] != "0" && args[2] != "0" {
		outputProxyClient = output.NewOutputProxyClient()
		stdoutPort, err := strconv.Atoi(args[1])
		if err != nil {
			outputProxyClient = nil
			fmt.Fprintf(out, "SERVER CONNECT ERROR: %v\r\n", err)
		}
		stderrPort, err := strconv.Atoi(args[2])
		if err != nil {
			outputProxyClient = nil
			fmt.Fprintf(out, "SERVER CONNECT ERROR: %v\r\n", err)
		}

		fmt.Fprintf(out, "Got server ports %d / %d\n\n", stdoutPort, stderrPort)

		if outputProxyClient != nil {
			err = outputProxyClient.Connect(stdoutPort, stderrPort)
			if err != nil {
				outputProxyClient = nil
			}
			fmt.Fprintf(out, "SERVER CONNECT ERROR: %v\r\n", err)
		}

		if outputProxyClient != nil {
			os.Stdout = outputProxyClient.Stdout
			os.Stderr = outputProxyClient.Stderr
			cli.ErrWriter = outputProxyClient.Stderr
		}
	}
	args = args[3:]

	os.Args = args

	C.report_running()

	exiter := func(code int) {
		if outputProxyClient != nil {
			outputProxyClient.Close()
		}
		C.report_stopped()
	}
	defer exiter(0)

	cli.OsExiter = exiter
	logrus.RegisterExitHandler(func() {
		exiter(-1)
	})

	cliApp := app.MakeApp()
	cliApp.Writer = os.Stdout
	cliApp.ErrWriter = os.Stderr
	err := cliApp.Run(args)
	if err != nil {
		fmt.Println(err)
		logrus.Error(err)
		logrus.Fatal("Aborting.")
	}
}

func initializeNative() error {
	if C.startServiceDispatcher() != C.int(0) {
		return &NotInServiceModeError{Underlying: windows.GetLastError()}
	}
	return nil
}
