package arch

type T int

const (
	Invalid T = iota
	AMD64
	I386
)

var bitness = map[T]Bitness{
	Invalid: BitnessInvalid,
	AMD64:   Bitness64Bit,
	I386:    Bitness32Bit,
}

func (t T) Bitness() Bitness {
	return bitness[t]
}
