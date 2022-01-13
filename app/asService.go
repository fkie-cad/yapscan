package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/fkie-cad/yapscan/service/output"

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

	fmt.Println("WARNING: This feature is experimental!")

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

	fmt.Println("Starting output proxy...")
	proxy := output.NewOutputProxyServer()
	err = proxy.Listen()
	defer proxy.Close()

	outputReadyForConnection := &sync.WaitGroup{}
	connectionSuccess := false
	waitConnection := &sync.WaitGroup{}

	if err != nil {
		proxy = nil
		fmt.Printf("WARNING: Could not start output proxy, the service will still be started, but no output will be visible. Reason: %v\n", err)
	} else {
		outputReadyForConnection.Add(1)
		waitConnection.Add(1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			defer func() {
				waitConnection.Done()
			}()

			outputReadyForConnection.Done()
			var err error
			err = proxy.WaitForConnection(ctx)

			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				fmt.Println("WARNING: Output proxy connection timed out. The service was likely still started, but no output will be visible.")
				return
			}
			if err != nil {
				fmt.Printf("WARNING: Service did not connect to output proxy. The service was likely still started, but no output will be visible. Reason: %v\n", err)
				return
			}

			connectionSuccess = true
		}()
		fmt.Println("Done, proxy is waiting for connections.")
	}

	scStartArguments := []string{"start", serviceName}
	if proxy != nil {
		scStartArguments = append(scStartArguments, strconv.Itoa(proxy.StdoutPort()), strconv.Itoa(proxy.StderrPort()))
	} else {
		scStartArguments = append(scStartArguments, "0", "0")
	}
	scStartArguments = append(scStartArguments, args...)

	outputReadyForConnection.Wait()

	fmt.Println("Starting service with arguments...")
	err = run("sc.exe", scStartArguments...)
	if err != nil {
		return cli.Exit(fmt.Sprintf("FAILURE: %v\n", err), 11)
	}
	fmt.Println("Done starting service, yapscan should now be running as a service with the following arguments")
	fmt.Println(args)

	if proxy != nil {
		waitConnection.Wait()
		if !connectionSuccess {
			return nil
		}

		fmt.Println()
		fmt.Println("========== Yapscan Service Output ==========")

		outputDone := &sync.WaitGroup{}
		outputDone.Add(1)
		go func() {
			var err error
			defer func() {
				outputDone.Done()
			}()

			err = proxy.ReceiveAndOutput(context.Background(), os.Stdout, os.Stderr)
			if err != nil {
				fmt.Printf("WARNING: Output proxy connection broke. The service might still be running, but you will not see any further output. Reason: %v\n", err)
			}
		}()
		outputDone.Wait()
	}

	return nil
}
