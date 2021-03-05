package arch

type ErrNotImplemented struct {
	Message string
}

func (e *ErrNotImplemented) Error() string {
	return e.Message
}
