package yapscan

import (
	"bytes"
	"fmt"
	"fraunhofer/fkie/yapscan/procIO"
	"reflect"
	"strings"
	"text/template"

	"github.com/dustin/go-humanize"
)

type FilterMatch struct {
	Result bool
	MSI    *procIO.MemorySegmentInfo
	Reason string // Reason for filter mismatch, if Result is false
}

type MemorySegmentFilterFunc func(info *procIO.MemorySegmentInfo) bool

type MemorySegmentFilter interface {
	Filter(info *procIO.MemorySegmentInfo) *FilterMatch
}

type baseFilter struct {
	filter         MemorySegmentFilterFunc
	Parameter      interface{}
	reasonTemplate string
}

func (f *baseFilter) renderReason(info *procIO.MemorySegmentInfo) string {
	t := template.New("filterReason")

	t.Funcs(template.FuncMap{
		"bytes": humanize.Bytes,
		"join": func(glue string, slice interface{}) string {
			s := reflect.ValueOf(slice)
			if s.Kind() != reflect.Slice {
				panic("argument is not a slice")
			}
			parts := make([]string, s.Len(), s.Len())
			for i := 0; i < s.Len(); i++ {
				str, ok := s.Index(i).Interface().(fmt.Stringer)
				if !ok {
					panic("slice does not contain implementations of the fmt.Stringer interface")
				}
				parts[i] = str.String()
			}
			return strings.Join(parts, glue)
		},
	})

	_, err := t.Parse(f.reasonTemplate)
	if err != nil {
		panic("could not parse filter reason template: " + err.Error())
	}

	buf := &bytes.Buffer{}
	err = t.Execute(buf, &struct {
		Filter MemorySegmentFilter
		MSI    *procIO.MemorySegmentInfo
	}{
		Filter: f,
		MSI:    info,
	})

	if err != nil {
		panic(err)
	}

	return buf.String()
}

func (f *baseFilter) Filter(info *procIO.MemorySegmentInfo) *FilterMatch {
	var reasonForMismatch string

	matches := f.filter(info)
	if !matches {
		reasonForMismatch = f.renderReason(info)
	}

	return &FilterMatch{
		Result: matches,
		MSI:    info,
		Reason: reasonForMismatch,
	}
}

func NewFilterFromFunc(filter MemorySegmentFilterFunc, parameter interface{}, reasonTemplate string) MemorySegmentFilter {
	return &baseFilter{
		filter:         filter,
		Parameter:      parameter,
		reasonTemplate: reasonTemplate,
	}
}

func NewMaxSizeFilter(size uint64) MemorySegmentFilter {
	return NewFilterFromFunc(
		func(info *procIO.MemorySegmentInfo) bool {
			return info.Size <= size
		},
		size,
		"segment too large, size: {{.MSI.Size|bytes}}, max-size: {{.Filter.Parameter|bytes}}",
	)
}

func NewMinSizeFilter(size uint64) MemorySegmentFilter {
	return NewFilterFromFunc(
		func(info *procIO.MemorySegmentInfo) bool {
			return info.Size >= size
		},
		size,
		"segment too small, size: {{.MSI.Size|bytes}}, min-size: {{.Filter.Parameter|bytes}}",
	)
}

func NewStateFilter(states []procIO.State) MemorySegmentFilter {
	return NewFilterFromFunc(
		func(info *procIO.MemorySegmentInfo) bool {
			for _, s := range states {
				if info.State == s {
					return true
				}
			}
			return false
		},
		states,
		"segment has wrong state, state: {{.MSI.State}}, allowed states: {{.Filter.Parameter|join \", \"}}",
	)
}

func NewTypeFilter(types []procIO.Type) MemorySegmentFilter {
	return NewFilterFromFunc(
		func(info *procIO.MemorySegmentInfo) bool {
			for _, t := range types {
				if info.Type == t {
					return true
				}
			}
			return false
		},
		types,
		"segment has wrong type, type: {{.MSI.Type}}, allowed types: {{.Filter.Parameter|join \", \"}}",
	)
}

func NewPermissionsFilterExact(perms []procIO.Permissions) MemorySegmentFilter {
	return NewFilterFromFunc(
		func(info *procIO.MemorySegmentInfo) bool {
			for _, p := range perms {
				if info.CurrentPermissions.EqualTo(p) {
					return true
				}
			}
			return false
		},
		perms,
		"segment has wrong permissions, permissions: {{.MSI.CurrentPermissions}}, allowed permissions: {{.Filter.Parameter|join \", \"}}",
	)
}

func NewPermissionsFilter(perm procIO.Permissions) MemorySegmentFilter {
	return NewFilterFromFunc(
		func(info *procIO.MemorySegmentInfo) bool {
			return info.CurrentPermissions.IsMoreOrEquallyPermissiveThan(perm)
		},
		perm,
		"segment has wrong permissions, permissions: {{.MSI.CurrentPermissions}}, min-permissions: {{.Filter.Parameter}}",
	)
}

type andFilter struct {
	filters []MemorySegmentFilter
}

func NewAndFilter(filters ...MemorySegmentFilter) MemorySegmentFilter {
	return &andFilter{
		filters: filters,
	}
}

func (f *andFilter) Filter(info *procIO.MemorySegmentInfo) *FilterMatch {
	result := &FilterMatch{
		Result: true,
		MSI:    info,
	}
	reasons := make([]string, 0)
	for _, filter := range f.filters {
		if filter == nil {
			continue
		}

		r := filter.Filter(info)
		if !r.Result {
			result.Result = false
			reasons = append(reasons, result.Reason)
		}
	}
	if !result.Result {
		result.Reason = strings.Join(reasons, " AND ")
	}
	return result
}
