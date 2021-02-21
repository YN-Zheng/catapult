// har -> wprgo convertor

package webpagereplay

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"github.com/mrichman/hargo"
	"github.com/urfave/cli"
)

type HarConvertorConfig struct {
	harFile, outputFile string
	keyFile, certFile   string

	// Computed states
	tlsCert  tls.Certificate
	x509Cert *x509.Certificate
}

func (cfg *HarConvertorConfig) Flags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{
			Name:        "https_cert_file",
			Value:       "wpr_cert.pem",
			Usage:       "File containing a PEM-encoded X509 certificate to use with SSL.",
			Destination: &cfg.certFile,
		},
		cli.StringFlag{
			Name:        "https_key_file",
			Value:       "wpr_key.pem",
			Usage:       "File containing a PEM-encoded private key to use with SSL.",
			Destination: &cfg.keyFile,
		},
		cli.StringFlag{
			Name:        "har_file",
			Usage:       "A single .har file or a directory that contains multiple .har.gz files(as downloaded from Http Archive)",
			Destination: &cfg.harFile,
		},
		cli.StringFlag{
			Name:        "output_file",
			Usage:       "path to output_file or files (according to har_file)",
			Destination: &cfg.outputFile,
		},
	}
}

func (cfg *HarConvertorConfig) HarConvert(c *cli.Context) {

	// open a writable archive
	//
	if cfg.outputFile == "" {
		cfg.outputFile = cfg.harFile + ".wprgo"
	}
	archive, err := OpenWritableArchive(cfg.outputFile)
	if err != nil {
		log.Fatal("Cannot open output file: ", cfg.outputFile)
	}

	// convert .har file(s).Note that cfg.harFile can be a folder or a single file
	fi, err := os.Stat(cfg.harFile)
	if err != nil {
		log.Fatal(err)
	}
	switch mode := fi.Mode(); {
	case mode.IsDir():
		// if convert all .har.gz files in one folder: HttpArchive -> HttpArchive.wprgo
		archive.convertHars(cfg)
	case mode.IsRegular():
		// if convert single har file: example.har -> example.har.wprgo
		archive.convertSingleHar(cfg)
	}
	archive.Close()
	log.Println("Conversion completed")

}

// convertHars will convert all har.gz files into one .wprgo archive.
// example: cfg.harFile = 'tmp/HttpArchive'.
// Then all *.har.gz in directory 'tmp/HttpArchive' will be read and write into tmp/HttpArchive.wprgo
// A 'hostnames.txt' will also be generated in that directory, summarying all websites that has been recored in .wprgo Archive.
func (archive *WritableArchive) convertHars(cfg *HarConvertorConfig) {

	// dealing with downloaded har.gz files using gsutil
	gzfiles, err := ioutil.ReadDir(cfg.harFile)
	if err != nil {
		log.Fatal(err)
	}
	var hostnames []string
	for i, gzfile := range gzfiles {
		if !strings.HasSuffix(gzfile.Name(), ".har.gz") {
			continue
		}
		gf, _ := os.Open(cfg.harFile + "/" + gzfile.Name())
		defer gf.Close()
		f, err := gzip.NewReader(gf)
		defer f.Close()
		if err != nil {
			log.Fatal("Cannot open har file: ", cfg.harFile)
		}
		dec := json.NewDecoder(hargo.NewReader(f))
		var har hargo.Har
		dec.Decode(&har)

		log.Println("Conversion started: " + gzfile.Name())
		archive.AppendHar(har)
		hostnames = append(hostnames, har.Log.Entries[0].Request.URL)
		if i > 1000 { // TODO test how many har files can be stored in one archive.wprgo file
			break
		}
	}
	// write converted hostnames (for replay)
	if err := writeLines(hostnames, cfg.harFile+"/"+"hostnames.txt"); err != nil {
		log.Fatalf("writeLines: %s", err)
	}
	log.Printf("Convert %d har files in total.\n", len(hostnames))
}

// writeLines writes the lines to the given file.
func writeLines(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	w := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}

func (archive *WritableArchive) convertSingleHar(cfg *HarConvertorConfig) {
	f, err := os.Open(cfg.harFile)
	defer f.Close()
	if err != nil {
		log.Fatal("Cannot open har file: ", cfg.harFile)
	}
	dec := json.NewDecoder(hargo.NewReader(f))
	var har hargo.Har
	dec.Decode(&har)

	log.Println("Conversion started")
	archive.AppendHar(har)
}

// AppendHar parse harfile into http.Archive which can be saved as *.wprgo
func (archive *WritableArchive) AppendHar(har hargo.Har) error {
	//_, err := Validate(r)

	for i, entry := range har.Log.Entries {

		if !assertCompleteEntry(entry) {
			continue
		}
		req, _ := hargo.EntryToRequest(&entry, false)
		resp, _ := EntryToResponse(&entry, req)

		err := archive.RecordRequest(req, resp)
		if err != nil {
			fmt.Printf(string(rune(i)) + err.Error())
		}
	}
	return nil
}

func assertCompleteEntry(entry hargo.Entry) bool {
	if entry.Time > 50000 && entry.Request.Method == "" {
		log.Println("damaged entry")
		return false
	}
	return true
}

// EntryToResponse parse a harfile entry into a http.Response
func EntryToResponse(entry *hargo.Entry, req *http.Request) (*http.Response, error) {

	rw := httptest.NewRecorder()
	for _, nvp := range entry.Response.Headers {
		rw.HeaderMap.Add(nvp.Name, nvp.Value)
	}
	var n int
	// For responses corresponding to fonts/image files, response body in harfile is encoded into Base64.
	// These bodies need to be decoded first
	// (Alghough they will be encoded into Base64 later during archive.serializeRequest)
	if ec := entry.Response.Content.Encoding; ec != "" {
		if ec == "base64" {
			decoded, err := base64.StdEncoding.DecodeString(entry.Response.Content.Text)
			if err != nil {
				log.Fatal(err)
			}
			entry.Response.Content.Text = string(decoded)
		} else {
			log.Printf("Missing encoding in harfile: %s", ec)
		}
	}

	// Compress data according to content_encoding, so that browser can analysze it correctly
	if contentEncodings, ok := rw.HeaderMap["Content-Encoding"]; ok {
		// compress body by given content_encoding
		// only one encoding method is expected
		if len(contentEncodings) != 1 {
			log.Fatal("Multiple content_encoding")
		}
		contentEncoding := contentEncodings[0]
		var err error
		var b bytes.Buffer

		var wc io.WriteCloser

		switch contentEncoding {
		case "gzip", "x_gzip":
			wc = gzip.NewWriter(&b)
			if _, err = wc.Write([]byte(entry.Response.Content.Text)); err != nil {
				log.Fatal(err)
			}
			if err = wc.Close(); err != nil {
				log.Fatal(err)
			}
		case "deflate":
			wc, err = flate.NewWriter(&b, -1)
			if err != nil {
				log.Fatal(err)
			}
			if _, err = wc.Write([]byte(entry.Response.Content.Text)); err != nil {
				log.Fatal(err)
			}
			if err = wc.Close(); err != nil {
				log.Fatal(err)
			}
		case "br":
			log.Fatal("Missing Content-Encoding:  br")
		case "identity":
			w := bufio.NewWriter(&b)
			if _, err = w.Write([]byte(entry.Response.Content.Text)); err != nil {
				log.Fatal(err)
			}
			w.Flush()
		default:
			log.Fatal("Missing Content-Encoding:  " + contentEncoding)
		}

		n, _ = rw.Body.Write(b.Bytes())
		b.Reset()
		//TODO: br, deflate...

	} else {
		n, _ = rw.Body.WriteString(entry.Response.Content.Text)
	}

	rw.Code = entry.Response.Status
	resp := rw.Result()

	resp.Proto = strings.ToUpper(entry.Response.HTTPVersion)
	resp.ProtoMajor, resp.ProtoMinor, _ = http.ParseHTTPVersion(resp.Proto)

	resp.Request = req
	// Content_Length has to be the same with the real number of bytes that has been written.
	// Could be slightly different with the real situation.(since we compress data manually using gzip.... in golang)
	resp.ContentLength = int64(n)
	return resp, nil
}
