package yapscan

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/hillu/go-yara/v4"
)

// AddressesFromMatches returns one value for each given yara.MatchString.
// The returned values are equal to the given offset plus the Offset field of
// each yara.MatchString.
func AddressesFromMatches(matches []yara.MatchString, offset uint64) []uint64 {
	addrs := make([]uint64, len(matches))
	for i, m := range matches {
		addrs[i] = m.Offset + offset
	}
	return addrs
}

// FormatSlice calls fmt.Sprintf(format, element, args...) for each
// element in the given slice. The returned string slice contains the
// formatted output.
func FormatSlice(format string, slice interface{}, args ...interface{}) []string {
	ref := reflect.ValueOf(slice)
	if ref.Kind() != reflect.Slice {
		panic("argument \"slice\" must be a slice")
	}

	strs := make([]string, ref.Len())
	for i := 0; i < ref.Len(); i++ {
		printfArgs := make([]interface{}, 1, len(args)+1)
		printfArgs[0] = ref.Index(i).Interface()
		printfArgs = append(printfArgs, args...)

		strs[i] = fmt.Sprintf(format, printfArgs...)
	}

	return strs
}

// Join joins all elements of a string slice, using the defaultGlue
// for all but the last two elements.
func Join(parts []string, defaultGlue, finalGlue string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}

	n := (len(parts)-2)*len(defaultGlue) + len(finalGlue)
	for i := range parts {
		n += len(parts[i])
	}

	var b strings.Builder
	b.Grow(n)
	b.WriteString(parts[0])
	for _, part := range parts[1 : len(parts)-1] {
		b.WriteString(defaultGlue)
		b.WriteString(part)
	}
	b.WriteString(finalGlue)
	b.WriteString(parts[len(parts)-1])
	return b.String()
}
