package main

import (
	"os"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/fkie-cad/yapscan/app"
)

// Built using this example: https://docs.microsoft.com/en-us/windows/win32/services/writing-a-servicemain-function

// #include <windows.h>
//
// static char* SERVICE_NAME = "yapscan";
// static SERVICE_STATUS          gSvcStatus = {0};
// static SERVICE_STATUS_HANDLE   gSvcStatusHandle = NULL;
// static HANDLE                  ghSvcStopEvent = NULL;
//
// extern void __declspec(dllexport) ServiceMain(DWORD dwNumServicesArgs, LPSTR *lpServiceArgVectors);
// extern void __declspec(dllexport) ServiceCtrlHandler(DWORD dwCtrl);
//
// static int startServiceDispatcher() {
//     SERVICE_TABLE_ENTRY serviceTable[] = {
//	       {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
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
//     gSvcStatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
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

//export ServiceCtrlHandler
func ServiceCtrlHandler(dwCtrl C.DWORD) {
	// We could handle commands from the service manager, but let's just not...
}

//export ServiceMain
func ServiceMain(dwNumServicesArgs C.DWORD, lpServiceArgVectors **C.char) {
	if C.init_status() != C.int(0) {
		return
	}

	args := make([]string, dwNumServicesArgs)
	for i := range args {
		args[i] = C.GoString(C.arg_index(lpServiceArgVectors, C.int(i)))
	}
	os.Args = args

	C.report_running()

	exiter := func(code int) {
		C.report_stopped()
	}
	cli.OsExiter = exiter
	logrus.RegisterExitHandler(func() {
		exiter(-1)
	})

	app.RunApp(args)
}

func main() {
	if C.startServiceDispatcher() == C.int(0) {
		// Started as service.
		// The ServiceMain is called by the service manager, we can just exit.
		return
	} else {
		// Not a service, run normally
		app.RunApp(os.Args)
	}
}
