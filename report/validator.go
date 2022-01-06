package report

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
	// Enable HTTP loading of schemas by default
	_ "github.com/santhosh-tekuri/jsonschema/v5/httploader"
)

type Validator struct {
	compiler *jsonschema.Compiler
}

func newValidator() *Validator {
	return &Validator{
		compiler: jsonschema.NewCompiler(),
	}
}

func NewOfflineValidator(schemaRootPath string) *Validator {
	v := newValidator()

	schemaRootPath = strings.TrimRight(schemaRootPath, "/\\")

	v.compiler.LoadURL = func(url string) (io.ReadCloser, error) {
		if strings.Index(url, schemaURLBase) != 0 {
			return nil, fmt.Errorf("schema URL \"%s\" is invalid for yapscan reports", url)
		}
		path := schemaRootPath + url[len(schemaURLBase):]
		return os.Open(path)
	}

	return v
}

func NewOnlineValidator(schemaRootPath string) *Validator {
	return newValidator()
}

func (v *Validator) ValidateReport(rdr Reader) error {
	in, err := rdr.OpenMeta()
	if err != nil {
		return err
	}
	metaData, err := v.validateSingleObject(MetaV1Schema, in)
	in.Close()
	if err != nil {
		return err
	}

	schemaURLs := make(map[string]string)
	for file, url := range metaData["schemaURLs"].(map[string]interface{}) {
		schemaURLs[file] = url.(string)
	}

	in, err = rdr.OpenSystemInformation()
	if err != nil {
		return err
	}
	_, err = v.validateSingleObject(schemaURLs[SystemInfoFileName], in)
	in.Close()
	if err != nil {
		return err
	}

	in, err = rdr.OpenStatistics()
	if err != nil {
		return err
	}
	_, err = v.validateSingleObject(schemaURLs[ScanningStatisticsFileName], in)
	in.Close()
	if err != nil {
		return err
	}

	in, err = rdr.OpenProcesses()
	if err != nil {
		return err
	}
	err = v.validateMultipleObjects(schemaURLs[ProcessesFileName], in)
	in.Close()
	if err != nil {
		return err
	}

	in, err = rdr.OpenMemoryScans()
	if err != nil {
		return err
	}
	err = v.validateMultipleObjects(schemaURLs[MemoryScansFileName], in)
	in.Close()
	if err != nil {
		return err
	}

	in, err = rdr.OpenFileScans()
	if err != nil {
		return err
	}
	err = v.validateMultipleObjects(schemaURLs[FileScansFileName], in)
	in.Close()
	return err
}

func (v *Validator) validateSingleObject(schemaURL string, in io.Reader) (map[string]interface{}, error) {
	metaSchema, err := v.compiler.Compile(schemaURL)
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadAll(in)
	if err != nil {
		return nil, err
	}

	data := make(map[string]interface{})
	err = json.Unmarshal(b, &data)
	if err != nil {
		return nil, err
	}

	return data, metaSchema.Validate(data)
}

func (v *Validator) validateMultipleObjects(schemaURL string, in io.Reader) error {
	schema, err := v.compiler.Compile(schemaURL)
	if err != nil {
		return err
	}

	rdr := bufio.NewReader(in)
	for {
		var line string
		line, err = rdr.ReadString('\n')
		line = strings.Trim(line, " \n\r\t")
		if line != "" {
			data := make(map[string]interface{})
			validationErr := json.Unmarshal([]byte(line), &data)
			if validationErr != nil {
				return validationErr
			}
			validationErr = schema.Validate(data)
			if validationErr != nil {
				return validationErr
			}
		}
		if err != nil {
			break
		}
	}
	if err != nil && err != io.EOF {
		return err
	}

	return nil
}
