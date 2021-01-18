package fileio

func Enumerate(typeMask DriveType) ([]string, error) {
	return enumerateImpl(typeMask)
}
