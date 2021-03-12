package arch

// Native returns the native architecture T of the running process.
func Native() T {
	return get()
}
