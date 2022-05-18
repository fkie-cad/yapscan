package acceptanceTests

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fkie-cad/yapscan/procio"
	"github.com/fkie-cad/yapscan/report"
	"github.com/fkie-cad/yapscan/system"
	"github.com/fkie-cad/yapscan/testutil"
	"golang.org/x/crypto/openpgp"

	. "github.com/smartystreets/goconvey/convey"
)

func findReportPath(reportDir string) (string, bool) {
	var reportName string
	dir, _ := ioutil.ReadDir(reportDir)
	for _, entry := range dir {
		if !entry.IsDir() && strings.Contains(entry.Name(), ".tar.zst") {
			reportName = entry.Name()
			break
		}
	}
	return filepath.Join(reportDir, reportName), reportName != ""
}

type reportOpenFunc func(reportPath string) (report.Reader, error)

func openReportCleartext() reportOpenFunc {
	return func(reportPath string) (report.Reader, error) {
		return report.NewFileReader(reportPath), nil
	}
}

func openReportWithPassword(password string) reportOpenFunc {
	return func(reportPath string) (report.Reader, error) {
		rdr := report.NewFileReader(reportPath)
		rdr.SetPassword(password)
		return rdr, nil
	}
}

func openReportPGP(keyring openpgp.EntityList) reportOpenFunc {
	return func(reportPath string) (report.Reader, error) {
		rdr := report.NewFileReader(reportPath)
		rdr.SetKeyring(keyring)
		return rdr, nil
	}
}

func conveyReportIsValidAndHasMatch(c C, openReport reportOpenFunc, pid int, addressOfData uintptr, reportDir string) {
	c.Convey("should yield a valid report", func(c C) {
		reportPath, exists := findReportPath(reportDir)

		c.So(exists, ShouldBeTrue)
		if !exists {
			return
		}

		reportRdr, err := openReport(reportPath)
		So(err, ShouldBeNil)
		defer reportRdr.Close()

		projectRoot, err := testutil.GetProjectRoot()
		So(err, ShouldBeNil)

		validator := report.NewOfflineValidator(projectRoot + "/report")
		err = validator.ValidateReport(reportRdr)
		So(err, ShouldBeNil)

		conveyReportHasMatch(c, pid, addressOfData, reportRdr)
	})
}

func conveyReportIsValidButDoesNotHaveMatch(c C, openReport reportOpenFunc, pid int, addressOfData uintptr, reportDir string) {
	c.Convey("should yield a readable report", func(c C) {
		reportPath, exists := findReportPath(reportDir)

		c.So(exists, ShouldBeTrue)
		if !exists {
			return
		}

		reportRdr, err := openReport(reportPath)
		So(err, ShouldBeNil)
		defer reportRdr.Close()

		projectRoot, err := testutil.GetProjectRoot()
		So(err, ShouldBeNil)

		validator := report.NewOfflineValidator(projectRoot + "/report")
		err = validator.ValidateReport(reportRdr)
		So(err, ShouldBeNil)

		conveyReportDoesNotHaveMatch(c, pid, addressOfData, reportRdr)
	})
}

func conveyReportIsAnonymized(c C, openReport reportOpenFunc, reportDir string, hostname, username string, ips []string) {
	c.Convey("should yield a valid report", func(c C) {
		reportPath, exists := findReportPath(reportDir)

		c.So(exists, ShouldBeTrue)
		if !exists {
			return
		}

		reportRdr, err := openReport(reportPath)
		So(err, ShouldBeNil)
		defer reportRdr.Close()

		projectRoot, err := testutil.GetProjectRoot()
		So(err, ShouldBeNil)

		validator := report.NewOfflineValidator(projectRoot + "/report")
		err = validator.ValidateReport(reportRdr)
		So(err, ShouldBeNil)

		c.Convey("which does not contain the hostname, username or any IPs.", func(c C) {
			buffer := &bytes.Buffer{}

			r, err := reportRdr.OpenMeta()
			So(err, ShouldBeNil)
			_, err = io.Copy(buffer, r)
			So(err, ShouldBeNil)
			r.Close()

			r, err = reportRdr.OpenStatistics()
			So(err, ShouldBeNil)
			_, err = io.Copy(buffer, r)
			So(err, ShouldBeNil)
			r.Close()

			r, err = reportRdr.OpenSystemInformation()
			So(err, ShouldBeNil)
			_, err = io.Copy(buffer, r)
			So(err, ShouldBeNil)
			r.Close()

			r, err = reportRdr.OpenProcesses()
			So(err, ShouldBeNil)
			_, err = io.Copy(buffer, r)
			So(err, ShouldBeNil)
			r.Close()

			r, err = reportRdr.OpenMemoryScans()
			So(err, ShouldBeNil)
			_, err = io.Copy(buffer, r)
			So(err, ShouldBeNil)
			r.Close()

			r, err = reportRdr.OpenFileScans()
			So(err, ShouldBeNil)
			_, err = io.Copy(buffer, r)
			So(err, ShouldBeNil)
			r.Close()

			allJSON := buffer.String()

			So(allJSON, ShouldNotBeEmpty)
			So(allJSON, ShouldNotContainSubstring, hostname)
			for _, ip := range ips {
				So(allJSON, ShouldNotContainSubstring, ip)
			}
			So(allJSON, ShouldNotContainSubstring, username)
		})
	})
}

func conveyReportIsAnonymizedForLocalSystem(c C, openReport reportOpenFunc, reportDir string) {
	info, err := system.GetInfo()
	So(err, ShouldBeNil)

	self, err := procio.OpenProcess(os.Getpid())
	So(err, ShouldBeNil)

	selfInfo, err := self.Info()
	So(err, ShouldBeNil)

	conveyReportIsAnonymized(c, openReport, reportDir, info.Hostname, selfInfo.Username, info.IPs)
}

func conveyReportIsNotReadable(c C, openReport reportOpenFunc, reportDir string) {
	c.Convey("should not yield a readable report.", func(c C) {
		reportPath, exists := findReportPath(reportDir)

		c.So(exists, ShouldBeTrue)
		if !exists {
			return
		}

		reportRdr, err := openReport(reportPath)
		if err != nil {
			So(err, ShouldNotBeNil)
			return
		}
		defer reportRdr.Close()

		_, errMeta := reportRdr.OpenMeta()
		_, errStatistics := reportRdr.OpenStatistics()
		_, errSystemInformation := reportRdr.OpenSystemInformation()
		_, errProcesses := reportRdr.OpenProcesses()
		_, errMemoryScans := reportRdr.OpenMemoryScans()
		_, errFileScans := reportRdr.OpenFileScans()
		So(errMeta, ShouldNotBeNil)
		So(errStatistics, ShouldNotBeNil)
		So(errSystemInformation, ShouldNotBeNil)
		So(errProcesses, ShouldNotBeNil)
		So(errMemoryScans, ShouldNotBeNil)
		So(errFileScans, ShouldNotBeNil)
	})
}

func conveyReportHasMatch(c C, pid int, addressOfData uintptr, reportRdr report.Reader) {
	c.Convey("with the memory-scans.json containing the correct match.", func() {
		parser := report.NewParser()
		rprt, err := parser.Parse(reportRdr)
		So(err, ShouldBeNil)

		foundCorrectMatch := false
		for _, scan := range rprt.MemoryScans {
			if scan.PID == pid && scan.MemorySegment == addressOfData && len(scan.Matches) > 0 {
				foundCorrectMatch = true
				break
			}
		}
		c.So(foundCorrectMatch, ShouldBeTrue)
	})
}

func conveyReportDoesNotHaveMatch(c C, pid int, addressOfData uintptr, reportRdr report.Reader) {
	c.Convey("with the memory-scans.json not containing a false positive.", func() {
		parser := report.NewParser()
		rprt, err := parser.Parse(reportRdr)
		So(err, ShouldBeNil)

		foundMatchForPID := false
		foundMatchForAddressInPID := false
		for _, scan := range rprt.MemoryScans {
			if scan.PID == pid && len(scan.Matches) > 0 {
				foundMatchForPID = true
				if scan.MemorySegment == addressOfData {
					foundMatchForAddressInPID = true
					break
				}
			}
		}
		c.So(foundMatchForPID, ShouldBeFalse)
		c.So(foundMatchForAddressInPID, ShouldBeFalse)
	})
}

func withPGPKey(t *testing.T) (pubkeyPath, privkeyPath string, pubkey, privkey openpgp.EntityList) {
	publicKey := `-----BEGIN PGP PUBLIC KEY BLOCK-----

mI0EYJPogAEEAL4TyjkDBr36Bi3uIogDofX4tDCzLqq7D+eVo422Vb+vKACR7xb9
8b0viKzdxY+riRSYYABpCEdTSSnaxu33jdT8lLJng3nd1LzMOp/FfYP4NFs3lJJb
OossHfXRbn4It0iuS/Kh54stuQhXLKam+5wBiyNyQ7/UZY/URT6KoCk3ABEBAAG0
HEJvYiBTZWNyZXQgPGJvYkBzZWNyZXRzLmNvbT6IzAQTAQoANhYhBOK7KfeJOnY0
75mp8HCIYPeYHOjgBQJgk+iAAhsDBAsJCAcEFQoJCAUWAgMBAAIeAQIXgAAKCRBw
iGD3mBzo4P4PBAC5rliAt9pCeLxbISNXZJaCvGLYfsuz4xQah1U0D81lWUZE/oru
zlLd3kiTVL8Aufb2x22sg8kIuML2wiB7Ssa8CWk3K9zgDY+VTQqeJondhjCJlJNY
A3ePYO4Pzzn3PQSv66q5933DZDj4K7StFBqQBsCUc7lbVdH/dyK7rPJ4RLiNBGCT
6IABBAC4UNzRB3B8JptiHJvo6JypAxRuWzSQPceTIG0IAyUsIk4pVh2NvRARFIuD
c0mmgT5/SFaoRYF5HkVFs8unCBTMZ+BYIoXLqOnTeORJDXYcIl868G464D56nRfL
9/aIxJeP/3MWWonxfEXo5zKhqzbilPmJfojvxr3PKe4VCL6gBQARAQABiLYEGAEK
ACAWIQTiuyn3iTp2NO+ZqfBwiGD3mBzo4AUCYJPogAIbDAAKCRBwiGD3mBzo4Efc
BACqdYohgkt6V8RXiT+vuxYbfavY/TUn97j9Pd3Wea/m9RRvMWYuoFJm8v9OGF1r
aMd+ssVwzMgByyK/ppjALtyRQ5jxxerFZ9V/wXtd9i9gEXYja3yFoLfNCg0FAIKT
DseR8h7KG2EqdA3vRDoS6v7PkaTaoFvTizACRy7GJVki2w==
=06+X
-----END PGP PUBLIC KEY BLOCK-----
`
	privateKey := `-----BEGIN PGP PRIVATE KEY BLOCK-----

lQHYBGCT6IABBAC+E8o5Awa9+gYt7iKIA6H1+LQwsy6quw/nlaONtlW/rygAke8W
/fG9L4is3cWPq4kUmGAAaQhHU0kp2sbt943U/JSyZ4N53dS8zDqfxX2D+DRbN5SS
WzqLLB310W5+CLdIrkvyoeeLLbkIVyympvucAYsjckO/1GWP1EU+iqApNwARAQAB
AAP+OPcDXwy6I4tf+LnqnWrBSk9L6WB59u7y+EvPZXQkxLrAuVMDHZfjr/gj9PLN
953ICmUUOGtB8OZUAfgwMDdFyO/i+tZwbHXOAl1ZqzWn8tqnsRa/7SS+9Bgg+6ZU
9FUK8dQLUSSc3Ab+9k34TeAmv20GTZKiWCt6pwHjj0d9CJECANoHBfe2UC0qidiq
Ttofa/MAw9tBIta50ACLwyfoRzCmYmctIMBVIw1XXUMzYtJ9fBJqKTkXeRb6MrMb
YsjidbkCAN8ulNb85P+G902nbliJtjtPuMzPDROMnsSkEgIOW7rrIPhKAw8m0Ovh
gF3a8zIviRT++iIGla0GZXotlX13Dm8CANanph0ExqN8d/C9BBVmCF3q5ACikiAM
K8rsZsteCnvO8K2s9RR318BvMZ1UZrZInOC1OQI/pIWGVR+ZIjkQ4/mgHbQcQm9i
IFNlY3JldCA8Ym9iQHNlY3JldHMuY29tPojMBBMBCgA2FiEE4rsp94k6djTvmanw
cIhg95gc6OAFAmCT6IACGwMECwkIBwQVCgkIBRYCAwEAAh4BAheAAAoJEHCIYPeY
HOjg/g8EALmuWIC32kJ4vFshI1dkloK8Yth+y7PjFBqHVTQPzWVZRkT+iu7OUt3e
SJNUvwC59vbHbayDyQi4wvbCIHtKxrwJaTcr3OANj5VNCp4mid2GMImUk1gDd49g
7g/POfc9BK/rqrn3fcNkOPgrtK0UGpAGwJRzuVtV0f93Irus8nhEnQHYBGCT6IAB
BAC4UNzRB3B8JptiHJvo6JypAxRuWzSQPceTIG0IAyUsIk4pVh2NvRARFIuDc0mm
gT5/SFaoRYF5HkVFs8unCBTMZ+BYIoXLqOnTeORJDXYcIl868G464D56nRfL9/aI
xJeP/3MWWonxfEXo5zKhqzbilPmJfojvxr3PKe4VCL6gBQARAQABAAP+JurOASXK
urAVKXVkdxxcbbRMhVOlKNqej+JuGx285NF2gvRfp5yWrqCRp6b5U1qhRVNTFtMc
OCRr2ICS3NkQOM9yioh3W5ZozIAAQfSnMEKwc7BhHvUWdFfrRjU4uaQFTCyn8VxO
9tQBxwXbbZy5zFjHM4Po4ygNsXwzc6pXkgECAMPnjAEteqdEAh4nNR0e//oMO1b8
9HHU2SnYvN02yPB47fLiVLjEcaMfN0jAkarimQDLzlGJYiB520VnLYET/gECAPDb
Qfd0F+agMzbq50paw+7GkifjPSZOL+AsPyUOCP30RfvugpHSr/2fRuvwVxqIHTkv
VwE873vbULk+E5iuqgUCAJTjwNqs774bUch3LQnjI7qyiL1GcnKhO/6hdu6Hra/x
IB4iWRlU1MPf1MBxbXNAF5qfpx7mxwrK2md5s5stliiio4i2BBgBCgAgFiEE4rsp
94k6djTvmanwcIhg95gc6OAFAmCT6IACGwwACgkQcIhg95gc6OBH3AQAqnWKIYJL
elfEV4k/r7sWG32r2P01J/e4/T3d1nmv5vUUbzFmLqBSZvL/Thhda2jHfrLFcMzI
Acsiv6aYwC7ckUOY8cXqxWfVf8F7XfYvYBF2I2t8haC3zQoNBQCCkw7HkfIeyhth
KnQN70Q6Eur+z5Gk2qBb04swAkcuxiVZIts=
=2Tor
-----END PGP PRIVATE KEY BLOCK-----
`
	pubkeyPath = filepath.Join(t.TempDir(), "pubkey.pgp")
	err := ioutil.WriteFile(pubkeyPath, []byte(publicKey), 0600)
	if err != nil {
		t.Fatal("could not create test keypair", err)
	}
	pubkey, err = openpgp.ReadArmoredKeyRing(bytes.NewReader([]byte(publicKey)))
	if err != nil {
		t.Fatal("could not create test pgp keys", err)
	}

	privkeyPath = filepath.Join(t.TempDir(), "privkey.pgp")
	err = ioutil.WriteFile(privkeyPath, []byte(publicKey), 0600)
	if err != nil {
		t.Fatal("could not create test keypair", err)
	}
	privkey, err = openpgp.ReadArmoredKeyRing(bytes.NewReader([]byte(privateKey)))
	if err != nil {
		t.Fatal("could not create test pgp keys", err)
	}

	return
}
