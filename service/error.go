package service

import (
	"fmt"
)

type NotInServiceModeError struct {
	Underlying error
}

func (e *NotInServiceModeError) Error() string {
	return fmt.Sprintf("not running in service mode, %v", e.Underlying)
}

func (e *NotInServiceModeError) Unwrap() error {
	return e.Underlying
}

func IsNotInServiceModeError(err error) bool {
	_, ok := err.(*NotInServiceModeError)
	return ok
}
