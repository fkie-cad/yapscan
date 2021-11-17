package main

import (
	"fmt"
	"os"

	"github.com/fkie-cad/yapscan/service"
	"github.com/sirupsen/logrus"

	"github.com/fkie-cad/yapscan/app"
)

var onExit func()

func runApp(args []string) {
	err := app.MakeApp(args).Run(args)

	if err != nil {
		fmt.Println(err)
		logrus.Error(err)
		logrus.Fatal("Aborting.")
	}
	if onExit != nil {
		onExit()
	}
}

func svcMain(args []string) error {
	runApp(args)
	return nil
}

func main() {
	err := service.Initialize(svcMain)
	if service.IsNotInServiceModeError(err) {
		// Not a service, run normally
		runApp(os.Args)
	} else if err != nil {
		logrus.Fatal(err)
	}
	// Started as service.
	// The ServiceMain is called by the service manager, we can just exit.
}
