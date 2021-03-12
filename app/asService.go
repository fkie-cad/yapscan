package app

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func run(cmdName string, cmdArgs ...string) error {
	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func asService(args []string) {
	serviceName := "yapscan"

	binpath, err := filepath.Abs(args[0])
	if err != nil {
		fmt.Printf("ERROR: Could not determine absolute path of yapscan.exe, %v\n", err)
		os.Exit(1)
	}

	args = args[2:]
	scStartArguments := []string{"start", serviceName}
	scStartArguments = append(scStartArguments, args...)

	fmt.Println("WARNING: This feature is experimental!")
	fmt.Println("WARNING: You will not see any output of the executed service. Using --log-path is strongly advised.")

	fmt.Println("Removing service in case it exists already...")
	run("sc.exe", "delete", "yapscan")
	fmt.Println("Done removing.")

	fmt.Println("Installing service...")
	err = run("sc.exe", "create", serviceName, "type=", "own", "start=", "demand", "binpath=", binpath)
	if err != nil {
		fmt.Println("FAILURE")
		fmt.Print(err)
		os.Exit(10)
	}
	fmt.Println("Done installing service.")

	fmt.Println("Starting service with arguments...")
	err = run("sc.exe", scStartArguments...)
	if err != nil {
		fmt.Println("FAILURE")
		fmt.Print(err)
		os.Exit(11)
	}
	fmt.Println("Done starting service, yapscan should now be running as a service with the following arguments")
	fmt.Println(args)
}
