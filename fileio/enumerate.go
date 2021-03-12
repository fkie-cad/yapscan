package fileio

// Enumerate enumerates all mounted drives of the given type.
func Enumerate(typeMask DriveType) ([]string, error) {
	return enumerateImpl(typeMask)
}
