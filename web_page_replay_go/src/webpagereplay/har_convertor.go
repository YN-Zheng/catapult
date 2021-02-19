// har -> wprgo convertor

package webpagereplay

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
			Destination: &cfg.harFile,
		},
		cli.StringFlag{
			Name:        "output_file",
			Destination: &cfg.outputFile,
		},
	}
}

func (r *HarConvertorConfig) HarConvert(c *cli.Context) {

	file, err := os.Open(r.harFile)
	if err != nil {
		log.Fatal("Cannot open har file: ", r.harFile)
	}
	// example.har -> example_converted.wprgo
	if r.outputFile == "" {
		r.outputFile = r.harFile[:len(r.harFile)-4] + "_converted.wprgo"
	}

	archive, err := OpenWritableArchive(r.outputFile)
	if err == nil {
		r := hargo.NewReader(file)
		log.Println("Conversion started")
		Dump(r, archive)
		log.Println("Conversion completed")
	} else {
		log.Fatal("Cannot open output file: ", r.outputFile)
	}

}

// Dump parse harfile into http.Archive which can be saved as *.wprgo
func Dump(r *bufio.Reader, archive *WritableArchive) error {
	//_, err := Validate(r)

	dec := json.NewDecoder(r)

	var har hargo.Har
	dec.Decode(&har)
	for _, entry := range har.Log.Entries {

		req, _ := hargo.EntryToRequest(&entry, false)
		resp, _ := EntryToResponse(&entry, req)

		err := archive.RecordRequest(req, resp)
		if err != nil {
			fmt.Printf(err.Error())
		}
	}
	archive.Close()
	return nil

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
		}
	}

	// Compress data according to content_encoding, so that browser can analysze it correctly
	// TODO:(alternative) set all content_encoding to 'identity'.
	if contentEncodings, ok := rw.HeaderMap["Content-Encoding"]; ok {
		// compress body by given content_encoding
		// only one encoding method is expected
		if len(contentEncodings) != 1 {
			log.Fatal("Multiple content_encoding")
		}
		contentEncoding := contentEncodings[0]
		if contentEncoding == "gzip" || contentEncoding == "x_gzip" {
			var b bytes.Buffer
			gz := gzip.NewWriter(&b)
			if _, err := gz.Write([]byte(entry.Response.Content.Text)); err != nil {
				log.Fatal(err)
			}
			if err := gz.Close(); err != nil {
				log.Fatal(err)
			}
			n, _ = rw.Body.Write(b.Bytes())
		}
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
