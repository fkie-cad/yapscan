// Package arch provides information about the currently
// CPU architecture.
package arch

// T describes a CPU architecture.
type T string

const (
	// Invalid describes an unknown architecture or an invalid enum value.
	Invalid T = "invalid"
	// AMD64 describes the amd64 architecture.
	AMD64 = "amd64"
	// I386 describes the i386 architecture.
	I386 = "i386"
)

var bitness = map[T]Bitness{
	Invalid: BitnessInvalid,
	AMD64:   Bitness64Bit,
	I386:    Bitness32Bit,
}

// Bitness returns the Bitness of the architecture.
func (t T) Bitness() Bitness {
	return bitness[t]
}
