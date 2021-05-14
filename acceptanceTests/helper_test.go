package acceptanceTests

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fkie-cad/yapscan/testutil"
	"golang.org/x/crypto/openpgp"

	"github.com/fkie-cad/yapscan/procio"
	"github.com/fkie-cad/yapscan/testutil/memory"
	. "github.com/smartystreets/goconvey/convey"
)

const testCompilerTimeout = 1 * time.Minute
const testerTimeout = 15 * time.Second
const yapscanTimeout = 10 * time.Second

var memoryTesterCompiler *testutil.Compiler

func initializeMemoryTester() io.Closer {
	var err error
	memoryTesterCompiler, err = memory.NewTesterCompiler()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testCompilerTimeout)
	memoryTesterCompiler.Compile(ctx)
	cancel()

	return memoryTesterCompiler
}

func withMemoryTester(t *testing.T, c C, data []byte) (pid int, addressOfData uintptr) {
	ctx, cancel := context.WithTimeout(context.Background(), testerTimeout)

	tester, err := memory.NewTester(
		ctx,
		memoryTesterCompiler,
		data,
		uintptr(procio.PermissionsToNative(procio.Permissions{Read: true})))
	if err != nil {
		t.Fatal("could not create memory tester process", err)
	}

	addressOfData, err = tester.WriteDataAndGetAddress()
	if err != nil || addressOfData == 0 {
		t.Fatal("could not write data to memory tester process", err)
	}

	if c != nil {
		c.Reset(func() {
			tester.Close()
			cancel()
		})
	} else {
		t.Cleanup(func() {
			tester.Close()
			cancel()
		})
	}

	return tester.PID(), addressOfData
}

func withYaraRulesFile(t *testing.T, rules []byte) string {
	tempDir := t.TempDir()
	yaraRulesFile := filepath.Join(tempDir, "rules.yar")
	err := ioutil.WriteFile(yaraRulesFile, rules, 0600)
	if err != nil {
		t.Fatal("could not write temporary rules file", err)
	}

	return yaraRulesFile
}

func withYaraRulesFileAndMatchingMemoryTester(t *testing.T, c C, data []byte) (yaraRulesPath string, pid int, addressOfData uintptr) {
	return withYaraRulesFileAndMemoryTester(t, c, data, data)
}

func withYaraRulesFileAndNotMatchingMemoryTester(t *testing.T, c C, data []byte) (yaraRulesPath string, pid int, addressOfData uintptr) {
	memoryData := make([]byte, len(data))
	copy(memoryData, data)

	replaceCount := rand.Intn(len(data)) + 1
	for i := 0; i < replaceCount; i++ {
		memoryData[rand.Intn(len(data))] ^= byte(rand.Intn(254) + 1)
	}

	return withYaraRulesFileAndMemoryTester(t, c, data, memoryData)
}

func withYaraRulesFileAndMemoryTester(t *testing.T, c C, ruleData []byte, memoryData []byte) (yaraRulesPath string, pid int, addressOfData uintptr) {
	ruleDataHexString := &strings.Builder{}
	for _, b := range ruleData {
		ruleDataHexString.WriteString(fmt.Sprintf("%02X ", b))
	}

	rule := fmt.Sprintf(`
rule rule1 {
    meta:
        description = "just a dummy rule"
        author = "some dude on the internet"
        date = "2020-01-01"

    strings:
        $str1 = { %s}

    condition:
        $str1
}
`, ruleDataHexString.String())

	yaraRulesPath = withYaraRulesFile(t, []byte(rule))
	pid, addressOfData = withMemoryTester(t, c, memoryData)
	return
}

func withCapturedOutput(t *testing.T) (stdout, stderr *bytes.Buffer, cleanup func()) {
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal("could not create pipe for output capture", err)
	}
	origOut := os.Stdout
	os.Stdout = stdoutW

	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatal("could not create pipe for output capture", err)
	}
	origErr := os.Stderr
	os.Stderr = stderrW

	stdoutB, stderrB := &bytes.Buffer{}, &bytes.Buffer{}

	startWG := &sync.WaitGroup{}
	endWG := &sync.WaitGroup{}

	copyFunc := func(dst io.Writer, src io.Reader) {
		startWG.Done()
		defer endWG.Done()
		io.Copy(dst, src)
	}
	startWG.Add(2)
	endWG.Add(2)
	go copyFunc(stdoutB, stdoutR)
	go copyFunc(stderrB, stderrR)

	startWG.Wait()

	return stdoutB, stderrB, func() {
		os.Stdout = origOut
		os.Stderr = origErr

		stdoutW.Close()
		stdoutR.Close()
		stderrW.Close()
		stderrR.Close()
		endWG.Wait()
	}
}

func withPGPKey(t *testing.T) (keyringPath string, keyring openpgp.EntityList) {
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
	keyringPath = filepath.Join(t.TempDir(), "pubkey.pgp")
	err := ioutil.WriteFile(keyringPath, []byte(publicKey), 0600)
	if err != nil {
		t.Fatal("could not create test keypair", err)
	}

	keyring, err = openpgp.ReadArmoredKeyRing(bytes.NewReader([]byte(privateKey)))
	if err != nil {
		t.Fatal("could not create test pgp keys", err)
	}
	return
}
