package yapscan

import "github.com/hillu/go-yara/v4"

type ScanResult struct {
}

type Scanner interface {
	ScanMem(buf []byte) (results []yara.MatchRule, err error)
}

type yaraScanner struct {
	rules *yara.Rules
}

func NewScanner(rules *yara.Rules) (Scanner, error) {
	return &yaraScanner{rules}, nil
}

func (s *yaraScanner) ScanMem(buf []byte) ([]yara.MatchRule, error) {
	var matches yara.MatchRules
	err := s.rules.ScanMem(buf, 0, 0, &matches)
	return matches, err
}
