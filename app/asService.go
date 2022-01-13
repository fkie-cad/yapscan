package app

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/urfave/cli/v2"
)

func run(cmdName string, cmdArgs ...string) error {
	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func asService(args []string) error {
	serviceName := "yapscan"

	binpath, err := filepath.Abs(args[0])
	if err != nil {
		return cli.Exit(fmt.Sprintf("ERROR: Could not determine absolute path of yapscan.exe, %v\n", err), 1)
	}

	scStartArguments := []string{"start", serviceName}
	scStartArguments = append(scStartArguments, args...)

	fmt.Println("WARNING: This feature is experimental!")
	fmt.Println("WARNING: You will not see any output of the executed service. Using --log-path is strongly advised.")

	fmt.Println("Removing service in case it exists already...")
	err = run("sc.exe", "delete", "yapscan")
	if err != nil {
		fmt.Printf("WARNING: Could not remove service, %v\n", err)
	} else {
		fmt.Println("Done removing.")
	}

	fmt.Println("Installing service...")
	err = run("sc.exe", "create", serviceName, "type=", "own", "start=", "demand", "binpath=", binpath)
	if err != nil {
		return cli.Exit(fmt.Sprintf("FAILURE: %v\n", err), 10)
	}
	fmt.Println("Done installing service.")

	fmt.Println("Starting service with arguments...")
	err = run("sc.exe", scStartArguments...)
	if err != nil {
		return cli.Exit(fmt.Sprintf("FAILURE: %v\n", err), 11)
	}
	fmt.Println("Done starting service, yapscan should now be running as a service with the following arguments")
	fmt.Println(args)
	return nil
}
