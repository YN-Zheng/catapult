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
	"net/url"
	"runtime"
	"sort"
	"strconv"

	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"github.com/mrichman/hargo"
	"github.com/urfave/cli"
	"golang.org/x/net/http/httpguts"
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

	// convert .har file(s).Note that cfg.harFile can be a folder or a single file
	fi, err := os.Stat(cfg.harFile)
	if err != nil {
		log.Fatal(err)
	}
	switch mode := fi.Mode(); {
	case mode.IsDir():
		// if convert all .har.gz files in one folder: HttpArchive -> HttpArchive.wprgo
		convertHars(cfg)
	case mode.IsRegular():
		// if convert single har file: example.har -> example.har.wprgo
		convertSingleHar(cfg)
	}
	log.Println("Conversion completed")

}

func listHarGz(harFile string) []os.FileInfo {
	files, err := ioutil.ReadDir(harFile)
	gzs := make([]os.FileInfo, len(files))
	j := 0
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".har.gz") {
			gzs[j] = f
			j++
		}
	}
	gzs = gzs[:j]
	if err != nil {
		log.Fatal(err)
	}
	sort.Slice(gzs, func(i, j int) bool {
		return strings.Compare(gzs[i].Name(), gzs[j].Name()) == -1
	})
	return gzs
}

// convertHars will convert all har.gz files into one .wprgo archive.
// example: cfg.harFile = 'tmp/HttpArchive'.
// Then all *.har.gz in directory 'tmp/HttpArchive' will be read and write into tmp/HttpArchive/wprgo/*.wprgo
// 'hostnames/*.txt' will also be generated in that directory, summarying all websites that has been recored in *.wprgo Archive.
func convertHars(cfg *HarConvertorConfig) {
	os.Mkdir(cfg.harFile+"/wprgo/", 0700)
	os.Mkdir(cfg.harFile+"/hostnames/", 0700)
	// make a list of *.har.gz files
	gzs := listHarGz(cfg.harFile)
	// divide into groups
	capacity := 50
	groups := len(gzs)/capacity + 1
	log.Printf("Conversion started: %d files per group, %d files in total", capacity, len(gzs))
	var gzfiles []os.FileInfo
	var har hargo.Har
	// decode(&har, cfg.harFile+"/160401_10_M0KQ.har.gz")
	for i := 0; i < groups; i++ {
		archive, err := OpenWritableArchive(cfg.harFile + "/wprgo/" + strconv.Itoa(i) + ".wprgo")
		if err != nil {
			log.Fatal(err.Error())
		}
		if i == groups-1 {
			gzfiles = gzs[i*capacity:]
		} else {
			gzfiles = gzs[i*capacity : (i+1)*capacity]
		}
		var size int64
		for _, file := range gzfiles {
			size += file.Size()
		}
		log.Printf("Converting: Group %d / %d. Total size: %d KB\n", i, groups, size>>10)
		hostnames := make([]string, len(gzfiles))
		// Convert
		for j, gzfile := range gzfiles {
			log.Printf("%d : %s--%dKB\n", j, gzfile.Name(), gzfile.Size()>>10)
			decode(&har, cfg.harFile+"/"+gzfile.Name())
			archive.AppendHar(har)
			hostnames[j] = har.Log.Entries[0].Request.URL + "," + gzfile.Name()

		}
		if err := writeLines(hostnames, cfg.harFile+"/hostnames/"+strconv.Itoa(i)+".txt"); err != nil {
			log.Fatalf("writeLines: %s", err)
		}
		runtime.GC()
		// debug.FreeOSMemory()
		archive.Close()
	}
	log.Printf("Convert %d har files in total.\n", len(gzs))
}

func decode(har *hargo.Har, path string) {
	gf, _ := os.Open(path)
	f, err := gzip.NewReader(gf)
	if err != nil {
		log.Fatal(err.Error())
	}
	// dec := json.NewDecoder(hargo.NewReader(f))
	// dec.Decode(&har)
	bytes, _ := io.ReadAll(hargo.NewReader(f))
	json.Unmarshal(bytes, &har)
	gf.Close()
	f.Close()
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

func convertSingleHar(cfg *HarConvertorConfig) {
	// open a writable archive
	if cfg.outputFile == "" {
		cfg.outputFile = cfg.harFile + ".wprgo"
	}
	archive, err := OpenWritableArchive(cfg.outputFile)
	if err != nil {
		log.Fatal(err.Error())
	}
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
	archive.Close()
}

// AppendHar parse harfile into http.Archive which can be saved as *.wprgo
func (archive *WritableArchive) AppendHar(har hargo.Har) error {
	//_, err := Validate(r)

	for i, entry := range har.Log.Entries {

		if !assertCompleteEntry(entry) {
			continue
		}
		req, _ := EntryToRequest(&entry, false)
		resp, _ := EntryToResponse(&entry, req)

		err := archive.RecordRequest(req, resp)
		if err != nil {
			fmt.Printf(string(rune(i)) + err.Error())
		}
	}
	return nil
}

func assertCompleteEntry(entry hargo.Entry) bool {
	u, err := url.Parse(entry.Request.URL)
	if err != nil {
		log.Println(err.Error())
		return false
	}
	if u.Host == "" || u.Scheme == "" || entry.Request.Method == "" {
		log.Printf("Damaged entry -- incomplete Request: %s %s", entry.Request.Method, entry.Request.URL)
		return false
	}
	if entry.Time > 50000 {
		log.Printf("Damaged entry -- timeout: %.0f ms %s URL: %s", entry.Time, entry.Request.Method, entry.Request.URL)
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
				log.Fatal("EntryToResponse:" + err.Error())
			}
			if err = wc.Close(); err != nil {
				log.Fatal("EntryToResponse:" + err.Error())
			}
		case "deflate":
			wc, err = flate.NewWriter(&b, -1)
			if err != nil {
				log.Fatal("EntryToResponse:" + err.Error())
			}
			if _, err = wc.Write([]byte(entry.Response.Content.Text)); err != nil {
				log.Fatal("EntryToResponse:" + err.Error())
			}
			if err = wc.Close(); err != nil {
				log.Fatal("EntryToResponse:" + err.Error())
			}
		case "br":
			log.Fatal("Missing Content-Encoding:  br")
		case "identity", "none", "utf8", "UTF-8", "utf-8", "":
			w := bufio.NewWriter(&b)
			if _, err = w.Write([]byte(entry.Response.Content.Text)); err != nil {
				log.Fatal("EntryToResponse:" + err.Error())
			}
			w.Flush()
		default:
			log.Println("Missing Content-Encoding:  " + contentEncoding)
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

// EntryToRequest parse a harfile entry into a http.Response
// it's the same as hargo.EntryToRequest, without checking cookies' name and value
func EntryToRequest(entry *hargo.Entry, ignoreHarCookies bool) (*http.Request, error) {
	body := ""

	if len(entry.Request.PostData.Params) == 0 {
		body = entry.Request.PostData.Text
	} else {
		form := url.Values{}
		for _, p := range entry.Request.PostData.Params {
			form.Add(p.Name, p.Value)
		}
		body = form.Encode()
	}

	req, _ := http.NewRequest(entry.Request.Method, entry.Request.URL, bytes.NewBuffer([]byte(body)))

	for _, h := range entry.Request.Headers {
		if httpguts.ValidHeaderFieldName(h.Name) && httpguts.ValidHeaderFieldValue(h.Value) && h.Name != "Cookie" {
			req.Header.Add(h.Name, h.Value)
		}
	}

	if !ignoreHarCookies {
		for _, c := range entry.Request.Cookies {
			cookie := &http.Cookie{Name: c.Name, Value: c.Value, HttpOnly: false, Domain: c.Domain}
			addCookie(req, cookie) //
		}
	}

	return req, nil
}

func addCookie(r *http.Request, c *http.Cookie) {
	s := fmt.Sprintf("%s=%s", sanitizeCookieName(c.Name), sanitizeCookieValue(c.Value))
	if c := r.Header.Get("Cookie"); c != "" {
		r.Header.Set("Cookie", c+"; "+s)
	} else {
		r.Header.Set("Cookie", s)
	}
}

func sanitizeCookieValue(v string) string {
	// v = sanitizeOrWarn("Cookie.Value", validCookieValueByte, v)
	if len(v) == 0 {
		return v
	}
	if strings.IndexByte(v, ' ') >= 0 || strings.IndexByte(v, ',') >= 0 {
		return `"` + v + `"`
	}
	return v
}

func validCookieValueByte(b byte) bool {
	return 0x20 <= b && b < 0x7f && b != '"' && b != ';' && b != '\\'
}

var cookieNameSanitizer = strings.NewReplacer("\n", "-", "\r", "-")

func sanitizeCookieName(n string) string {
	return cookieNameSanitizer.Replace(n)
}
