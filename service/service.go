package service

import "fmt"

type MainFunction func(args []string) error

var registeredMainFunction MainFunction

func Initialize(mainFunc MainFunction) error {
	if registeredMainFunction != nil {
		return fmt.Errorf("can only initialize one service")
	}
	registeredMainFunction = mainFunc

	return initializeNative()
}
