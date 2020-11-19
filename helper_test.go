package yapscan

import (
	"fmt"
	"testing"

	"github.com/hillu/go-yara/v4"

	. "github.com/smartystreets/goconvey/convey"
)

func ExampleJoin() {
	parts := []string{"life", "the universe", "everything"}
	fmt.Println(Join(parts, ", ", " and "))
	// Output: life, the universe and everything
}

func TestJoin(t *testing.T) {
	Convey("Joining an empty list", t, func() {
		parts := make([]string, 0)
		Convey("should yield an empty string.", func() {
			So(Join(parts, ", ", " and "), ShouldEqual, "")
		})
	})

	Convey("Joining just one element", t, func() {
		parts := []string{"test"}
		Convey("should yield the element itself.", func() {
			So(Join(parts, ", ", " and "), ShouldEqual, parts[0])
		})
	})

	Convey("Joining just two elements", t, func() {
		parts := []string{"test", "42"}
		Convey("should use the final glue only.", func() {
			So(Join(parts, ", ", " and "), ShouldEqual, "test and 42")
		})
	})

	Convey("Joining several elements", t, func() {
		parts := []string{"test", "42", "another", "test"}
		Convey("should use the final glue in the last glueing.", func() {
			So(Join(parts, ", ", " and "), ShouldEqual, "test, 42, another and test")
		})
	})
}

func TestAddressesFromMatches(t *testing.T) {
	Convey("An empty list", t, func() {
		list := make([]yara.MatchString, 0)
		Convey("should be fine.", func() {
			So(AddressesFromMatches(list, 0), ShouldResemble, []uint64{})
		})
	})

	Convey("A non empty list", t, func() {
		list := []yara.MatchString{
			yara.MatchString{
				Offset: 42,
			},
			yara.MatchString{
				Offset: 666,
			},
			yara.MatchString{
				Offset: 1337,
			},
		}

		Convey("with no offset applied", func() {
			result := AddressesFromMatches(list, 0)

			Convey("should just yield the original offsets.", func() {
				So(result, ShouldResemble, []uint64{
					42, 666, 1337,
				})
			})
		})

		Convey("with some offset applied", func() {
			result := AddressesFromMatches(list, 5)

			Convey("should yield the modified offsets.", func() {
				So(result, ShouldResemble, []uint64{
					5 + 42, 5 + 666, 5 + 1337,
				})
			})
		})
	})
}

func TestFormatSlice(t *testing.T) {
	Convey("Formatting with something that isn't a slice should panic.", t, func() {
		notASlice := 42
		So(func() {
			FormatSlice("fmt", notASlice)
		}, ShouldPanic)
	})

	Convey("Formatting a slice of ints", t, func() {
		ints := []int{42, 666, 1337}
		Convey("with no additional agruments", func() {
			Convey("should yield correctly formatted strings.", func() {
				So(FormatSlice("int: %d", ints), ShouldResemble, []string{
					"int: 42", "int: 666", "int: 1337",
				})
			})
		})
	})
}
