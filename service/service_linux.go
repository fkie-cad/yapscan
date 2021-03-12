package service

import "fmt"

func initializeNative() error {
	return &NotInServiceModeError{Underlying: fmt.Errorf("not implemented")}
}
