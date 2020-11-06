//go:generate go-enum -f=$GOFILE --marshal --lower --names
package arch

/*
ENUM(
Invalid
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

func (b Bitness) Short() string {
	return bitnessShortNames[b]
}
