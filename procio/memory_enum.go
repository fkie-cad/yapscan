// Code generated by go-enum DO NOT EDIT.
// Version: 0.5.3
// Revision: 8e2c93debfc66888870b2dfd86e70c79a70c920f
// Build Date: 2022-11-09T16:39:46Z
// Built By: goreleaser

package procio

import (
	"fmt"
	"strings"
)

const (
	// SegmentTypeImage is a SegmentType of type Image.
	SegmentTypeImage SegmentType = iota
	// SegmentTypeMapped is a SegmentType of type Mapped.
	SegmentTypeMapped
	// SegmentTypePrivate is a SegmentType of type Private.
	SegmentTypePrivate
	// SegmentTypePrivateMapped is a SegmentType of type PrivateMapped.
	SegmentTypePrivateMapped
)

var ErrInvalidSegmentType = fmt.Errorf("not a valid SegmentType, try [%s]", strings.Join(_SegmentTypeNames, ", "))

const _SegmentTypeName = "imagemappedprivateprivateMapped"

var _SegmentTypeNames = []string{
	_SegmentTypeName[0:5],
	_SegmentTypeName[5:11],
	_SegmentTypeName[11:18],
	_SegmentTypeName[18:31],
}

// SegmentTypeNames returns a list of possible string values of SegmentType.
func SegmentTypeNames() []string {
	tmp := make([]string, len(_SegmentTypeNames))
	copy(tmp, _SegmentTypeNames)
	return tmp
}

var _SegmentTypeMap = map[SegmentType]string{
	SegmentTypeImage:         _SegmentTypeName[0:5],
	SegmentTypeMapped:        _SegmentTypeName[5:11],
	SegmentTypePrivate:       _SegmentTypeName[11:18],
	SegmentTypePrivateMapped: _SegmentTypeName[18:31],
}

// String implements the Stringer interface.
func (x SegmentType) String() string {
	if str, ok := _SegmentTypeMap[x]; ok {
		return str
	}
	return fmt.Sprintf("SegmentType(%d)", x)
}

var _SegmentTypeValue = map[string]SegmentType{
	_SegmentTypeName[0:5]:                    SegmentTypeImage,
	strings.ToLower(_SegmentTypeName[0:5]):   SegmentTypeImage,
	_SegmentTypeName[5:11]:                   SegmentTypeMapped,
	strings.ToLower(_SegmentTypeName[5:11]):  SegmentTypeMapped,
	_SegmentTypeName[11:18]:                  SegmentTypePrivate,
	strings.ToLower(_SegmentTypeName[11:18]): SegmentTypePrivate,
	_SegmentTypeName[18:31]:                  SegmentTypePrivateMapped,
	strings.ToLower(_SegmentTypeName[18:31]): SegmentTypePrivateMapped,
}

// ParseSegmentType attempts to convert a string to a SegmentType.
func ParseSegmentType(name string) (SegmentType, error) {
	if x, ok := _SegmentTypeValue[name]; ok {
		return x, nil
	}
	return SegmentType(0), fmt.Errorf("%s is %w", name, ErrInvalidSegmentType)
}

// MarshalText implements the text marshaller method.
func (x SegmentType) MarshalText() ([]byte, error) {
	return []byte(x.String()), nil
}

// UnmarshalText implements the text unmarshaller method.
func (x *SegmentType) UnmarshalText(text []byte) error {
	name := string(text)
	tmp, err := ParseSegmentType(name)
	if err != nil {
		return err
	}
	*x = tmp
	return nil
}

const (
	// StateCommit is a State of type Commit.
	StateCommit State = iota
	// StateFree is a State of type Free.
	StateFree
	// StateReserve is a State of type Reserve.
	StateReserve
)

var ErrInvalidState = fmt.Errorf("not a valid State, try [%s]", strings.Join(_StateNames, ", "))

const _StateName = "commitfreereserve"

var _StateNames = []string{
	_StateName[0:6],
	_StateName[6:10],
	_StateName[10:17],
}

// StateNames returns a list of possible string values of State.
func StateNames() []string {
	tmp := make([]string, len(_StateNames))
	copy(tmp, _StateNames)
	return tmp
}

var _StateMap = map[State]string{
	StateCommit:  _StateName[0:6],
	StateFree:    _StateName[6:10],
	StateReserve: _StateName[10:17],
}

// String implements the Stringer interface.
func (x State) String() string {
	if str, ok := _StateMap[x]; ok {
		return str
	}
	return fmt.Sprintf("State(%d)", x)
}

var _StateValue = map[string]State{
	_StateName[0:6]:                    StateCommit,
	strings.ToLower(_StateName[0:6]):   StateCommit,
	_StateName[6:10]:                   StateFree,
	strings.ToLower(_StateName[6:10]):  StateFree,
	_StateName[10:17]:                  StateReserve,
	strings.ToLower(_StateName[10:17]): StateReserve,
}

// ParseState attempts to convert a string to a State.
func ParseState(name string) (State, error) {
	if x, ok := _StateValue[name]; ok {
		return x, nil
	}
	return State(0), fmt.Errorf("%s is %w", name, ErrInvalidState)
}

// MarshalText implements the text marshaller method.
func (x State) MarshalText() ([]byte, error) {
	return []byte(x.String()), nil
}

// UnmarshalText implements the text unmarshaller method.
func (x *State) UnmarshalText(text []byte) error {
	name := string(text)
	tmp, err := ParseState(name)
	if err != nil {
		return err
	}
	*x = tmp
	return nil
}
