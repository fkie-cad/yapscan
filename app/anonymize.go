package app

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/fkie-cad/yapscan/archiver"

	"github.com/fkie-cad/yapscan/pgp"
	"github.com/fkie-cad/yapscan/report"

	"github.com/fkie-cad/yapscan/output"
	"github.com/sirupsen/logrus"
	"github.com/targodan/go-errors"
	"github.com/urfave/cli/v2"
)

func anonymize(c *cli.Context) error {
	err := initAppAction(c)
	if err != nil {
		return err
	}

	if c.NArg() == 0 {
		return errors.Newf("expected at least one report path argument, got none")
	}

	var salt []byte
	base64Salt := c.String("salt")
	if base64Salt != "" {
		salt, err = base64.StdEncoding.DecodeString(base64Salt)
		if err != nil {
			return fmt.Errorf("could not decode given salt, reason: %w", err)
		}
	}
	if salt == nil {
		salt = output.GenerateRandomSalt(64)
	}

	rdrFactory := report.NewReaderFactory()

	inputWasEncrypted := false
	if c.String("decrypt-password") != "" && c.String("decrypt-pgpkey") != "" {
		return fmt.Errorf("cannot decrypt with both pgp key and a password")
	}
	if pass := c.String("decrypt-password"); pass != "" {
		inputWasEncrypted = true
		rdrFactory.SetPassword(pass)
	}
	if keypath := c.String("decrypt-pgpkey"); keypath != "" {
		inputWasEncrypted = true
		ring, err := pgp.ReadKeyRing(keypath)
		if err != nil {
			return fmt.Errorf("could not read specified public pgp key, reason: %w", err)
		}
		rdrFactory.SetKeyring(ring)
	}

	wcBuilder := output.NewWriteCloserBuilder()
	if c.String("password") != "" && c.String("pgpkey") != "" {
		return fmt.Errorf("cannot encrypt with both pgp key and a password")
	} else if inputWasEncrypted && c.String("pgpkey") == "" && c.String("pgpkey") == "" && c.Bool("decrypt") {
		fmt.Println("The input reports were encrypted. " +
			"You must either specify --pgpkey or --password for reencryption. " +
			"Alternatively you can specify --decrypt for permanent decryption of the reports.")
		return fmt.Errorf("no encryption options specified and decryption was not requested")
	}
	if c.String("password") != "" {
		wcBuilder.Append(output.PGPSymmetricEncryptionDecorator(c.String("password"), true))
	}
	if c.String("pgpkey") != "" {
		ring, err := pgp.ReadKeyRing(c.String("pgpkey"))
		if err != nil {
			return fmt.Errorf("could not read specified public pgp key, reason: %w", err)
		}
		wcBuilder.Append(output.PGPEncryptionDecorator(ring, true))
	}
	wcBuilder.Append(output.ZSTDCompressionDecorator())

	var multiErr error
	for _, inputPath := range c.Args().Slice() {
		fmt.Printf("Anonymizing %s...", inputPath)
		outputPath, err := anonymizeReport(inputPath, rdrFactory, salt, wcBuilder, c.String("output-dir"))
		multiErr = errors.NewMultiError(multiErr, err)
		if err == nil {
			fmt.Printf(" -> %s\n", outputPath)
		} else {
			fmt.Printf(" ERROR: %v\n", err)
		}
	}

	return multiErr
}

var nameRe = regexp.MustCompile("^(.+)_(.+)\\.tar.*$")

func anonymizeReport(
	inputPath string, rdrFactory *report.ReaderFactory,
	salt []byte,
	wcBuilder *output.WriteCloserBuilder,
	outDir string) (string, error) {
	inDir, inFile := filepath.Split(inputPath)

	rprt, err := func() (*report.Report, error) {
		rdr := rdrFactory.OpenFile(inputPath)
		defer func() {
			err := rdr.Close()
			if err != nil {
				fmt.Println(err)
				logrus.WithError(err).Error("Error closing the reader.")
			}
		}()

		parser := report.NewParser()

		rprt, err := parser.Parse(rdr)
		if err != nil {
			return nil, errors.Newf("could not read report, reason: %w", err)
		}
		return rprt, nil
	}()
	if err != nil {
		return "", err
	}

	anonymizer := output.NewReportAnonymizer(output.NewAnonymizerForOS(salt, rprt.SystemInfo.OSName))
	rprt = anonymizer.AnonymizeReport(rprt)

	nameParts := nameRe.FindStringSubmatch(inFile)
	if len(nameParts) != 3 {
		return "", errors.Newf("report filename \"%s\" has invalid format, "+
			"expected \"<hostname>_<timestamp>.tar[additionalExtensions]\"", inputPath)
	}
	hostname, timestamp := nameParts[1], nameParts[2]
	hostname = anonymizer.Anonymizer.Anonymize(hostname)

	outPath := fmt.Sprintf("%s_%s.tar%s", hostname, timestamp, wcBuilder.SuggestedFileExtension())

	if outDir != "" {
		outPath = filepath.Join(outDir, outPath)
	} else {
		outPath = filepath.Join(inDir, outPath)
	}
	reportTar, err := os.OpenFile(outPath, os.O_CREATE|os.O_RDWR, archivePermissions)
	if err != nil {
		return outPath, fmt.Errorf("could not create output report archive, reason: %w", err)
	}
	// reportTar is closed by the wrapping WriteCloser

	decoratedReportTar, err := wcBuilder.Build(reportTar)
	if err != nil {
		return outPath, fmt.Errorf("could not initialize archive, reason: %w", err)
	}
	reportArchiver := archiver.NewTarArchiver(decoratedReportTar)
	defer func() {
		err := reportArchiver.Close()
		if err != nil {
			fmt.Println(err)
			logrus.WithError(err).Error("Error closing the archiver.")
		}
	}()

	writer := report.NewReportWriter(reportArchiver)
	return outPath, writer.WriteReport(rprt)
}
