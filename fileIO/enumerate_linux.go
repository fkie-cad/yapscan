package fileIO

func enumerateImpl(typeMask DriveType) ([]string, error) {
	// TODO: Actually implement this.

	if typeMask&DriveTypeFixed != 0 {
		return []string{"/"}, nil
	}
	return []string{}, nil
}
