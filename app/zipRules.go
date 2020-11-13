package app

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/fkie-cad/yapscan"

	"github.com/yeka/zip"

	"github.com/targodan/go-errors"
	"github.com/urfave/cli/v2"
)

func zipRules(c *cli.Context) error {
	err := initAppAction(c)
	if err != nil {
		return err
	}

	if c.NArg() != 1 {
		return errors.Newf("expected exactly one argument, got %d", c.NArg())
	}

	rules, err := yapscan.LoadYaraRules(c.Args().Get(0), c.Bool("rules-recurse"))
	if err != nil {
		return err
	}

	outName := c.String("output")
	if outName == "" {
		outName = c.Args().Get(0)
		ext := filepath.Ext(outName)
		if len(ext) > 0 {
			outName = outName[:len(ext)]
		}
		outName += ".zip"
	}

	outFile, err := os.Create(outName)
	if err != nil {
		return fmt.Errorf("could not create output file \"%s\", reason: %w", outName, err)
	}
	defer outFile.Close()

	zipWriter := zip.NewWriter(outFile)
	defer zipWriter.Close()

	rulesWriter, err := zipWriter.Encrypt("rules.yarc", yapscan.RulesZIPPassword, zip.AES256Encryption)
	if err != nil {
		return fmt.Errorf("could not create rules file in zip \"%s\", reason: %w", outName, err)
	}

	err = rules.Write(rulesWriter)
	if err != nil {
		return fmt.Errorf("could not write rules file in zip \"%s\", reason: %w", outName, err)
	}

	return nil
}
