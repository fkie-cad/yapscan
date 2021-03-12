package main

import (
	"os"

	"github.com/fkie-cad/yapscan/service"
	"github.com/sirupsen/logrus"

	"github.com/fkie-cad/yapscan/app"
)

func svcMain(args []string) error {
	app.RunApp(args)
	return nil
}

func main() {
	err := service.Initialize(svcMain)
	if service.IsNotInServiceModeError(err) {
		// Not a service, run normally
		app.RunApp(os.Args)
	} else if err != nil {
		logrus.Fatal(err)
	}
	// Started as service.
	// The ServiceMain is called by the service manager, we can just exit.
	return
}
