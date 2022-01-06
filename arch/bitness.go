//go:generate go-enum -f=$GOFILE --marshal --lower --names
package arch

// Bitness describes the bitness of an architecture.
/*
ENUM(
invalid
32Bit = 32
64Bit = 64
)
*/
type Bitness int

var bitnessShortNames = map[Bitness]string{
	BitnessInvalid: "??",
	Bitness64Bit:   "64",
	Bitness32Bit:   "32",
}

// Short returns a short, human readable representation of a Bitness.
func (b Bitness) Short() string {
	return bitnessShortNames[b]
}
