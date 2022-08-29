package main

import (
	"encoding/csv"
	"errors"
	"fmt"
	"go/format"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var meaningNormalizer = regexp.MustCompile(`\n\s+`)

func main() {
	if err := entrypoint(); err != nil {
		fmt.Fprintf(os.Stderr, "unhandled error: %s\n", err)
	}
}

func entrypoint() (err error) {
	var wd string
	var projectRoot string

	if wd, err = os.Getwd(); err != nil {
		return
	}

	if projectRoot, err = resolveProjectRoot(wd); err != nil {
		return
	}

	targetFileName := filepath.Join(projectRoot, "internal/rule/flags_tcp_options.go")
	paramsFileName := filepath.Join(projectRoot, "hack/tcp-parameters-1.csv")

	var paramsFile *os.File
	if paramsFile, err = os.OpenFile(paramsFileName, os.O_RDONLY, 0); err != nil {
		err = fmt.Errorf("unable to open csv file: %w", err)
		return
	}
	defer func() { _ = paramsFile.Close() }()

	csvReader := csv.NewReader(paramsFile)

	var readErr error
	var records []string

	var buf strings.Builder
	buf.WriteString("package rule\n")
	buf.WriteString("\n")
	buf.WriteString("//go:generate go run ../../hack/parse_tcp_params.go\n")
	buf.WriteString("\n")
	buf.WriteString("var tcpOptPrefix = \"tcpopt:\"\n")
	buf.WriteString("\n")
	buf.WriteString("var validTCPOpts = map[string]bool{\n")

	headersSeen := false

	for records, readErr = csvReader.Read(); readErr != io.EOF; records, readErr = csvReader.Read() {
		if !headersSeen {
			headersSeen = true
			continue
		}
		if readErr != nil {
			err = fmt.Errorf("failed to process csv file: %w", readErr)
			return
		}

		var kinds []int
		var meaning string

		kindsRaw := records[0]
		if strings.Contains(kindsRaw, "-") {
			var begin int
			var end int
			split := strings.SplitN(kindsRaw, "-", 2)

			if begin, err = strconv.Atoi(split[0]); err != nil {
				err = fmt.Errorf("unable to parse kind range beginning: %w", err)
				return
			}

			if end, err = strconv.Atoi(split[1]); err != nil {
				err = fmt.Errorf("unable to parse kind range end: %w", err)
				return
			}

			for i := begin; i <= end; i++ {
				kinds = append(kinds, i)
			}
		} else {
			var kind int
			if kind, err = strconv.Atoi(kindsRaw); err != nil {
				err = fmt.Errorf("unable to parse kind: %w", err)
				return
			}

			kinds = append(kinds, kind)
		}

		meaningRaw := records[2]
		meaning = meaningNormalizer.ReplaceAllString(meaningRaw, " ")

		for _, kind := range kinds {
			buf.WriteString(fmt.Sprintf("\t(tcpOptPrefix+\"%d\"): true, // %s\n", kind, meaning))
		}
	}
	buf.WriteString("}\n")

	var fileBuf []byte
	if fileBuf, err = format.Source([]byte(buf.String())); err != nil {
		err = fmt.Errorf("failed to format generated code: %w", err)
		return
	}

	err = ioutil.WriteFile(targetFileName, fileBuf, 0644)

	return
}

func resolveProjectRoot(path string) (projectRoot string, err error) {
	projectRoot = path
	for {
		if _, err = os.Stat(filepath.Join(projectRoot, "go.mod")); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			return
		}

		projectRoot = filepath.Dir(projectRoot)
		if projectRoot == "/" {
			err = fmt.Errorf("failed to resolve project root")
			return
		}
	}
}
