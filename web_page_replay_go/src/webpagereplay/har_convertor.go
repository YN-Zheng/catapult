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

	"C"
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

const (
	MB = 1 << 20
)

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
		// convert all .har.gz files in one folder:
		// Will generate: ./wprgo/*.wprgo and ./hostnames/*.txt. * starts from 0. Each group contains approximate 150 websites
		convertHars(cfg.harFile)
	case mode.IsRegular():
		// convert single har file: example.har -> example.har.wprgo
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

// convertHars will convert all har.gz files into serveral .wprgo archive.
// example: cfg.harFile = 'tmp/HttpArchive'.
// Then all *.har.gz in directory 'tmp/HttpArchive' will be read and write into tmp/HttpArchive/wprgo/*.wprgo
// 'hostnames/*.txt' will also be generated in that directory, summarying all websites that has been recored in *.wprgo Archive.
func convertHars(harFile string) {
	os.Mkdir(harFile+"/wprgo/", 0700)
	os.Mkdir(harFile+"/hostnames/", 0700)
	// make a list of *.har.gz files
	gzs := listHarGz(harFile)
	var (
		har       hargo.Har
		archive   *WritableArchive
		hostnames []string
		err       error
	)

	// divide into groups
	groupSize := 0
	groupSizeThreshold := 300 // Better method. Instead of checking system's memory, check the summed unzipped size.

	hostnames = make([]string, 0)
	group, fileNumber := continueFromLog("./nohup.out")
	if group == 0 {
		log.Printf("Conversion started: %d files in total. ", len(gzs))
	} else {
		log.Printf("Conversion continued from group: %5d, file: %5d", group, fileNumber)
	}
	archive, err = OpenWritableArchive(harFile + "/wprgo/" + strconv.Itoa(group) + ".wprgo")
	for i, gzfile := range gzs {
		if i < fileNumber {
			continue
		}
		if groupSize>>20 > groupSizeThreshold {
			log.Printf("Saving group %d(%d files) \t -- %d/%d ", group, len(hostnames), i, len(gzs))
			if err := writeLines(hostnames, harFile+"/hostnames/"+strconv.Itoa(group)+".txt"); err != nil {
				log.Fatalf("writeLines: %s", err)
			}
			runtime.GC()
			archive.Close()
			group++
			groupSize = 0
			if archive, err = OpenWritableArchive(harFile + "/wprgo/" + strconv.Itoa(group) + ".wprgo"); err != nil {
				log.Fatalf("openWriteableArchive: %s", err)
			}
			hostnames = make([]string, 0)

		}
		gf, _ := os.Open(harFile + "/" + gzfile.Name())
		f, err := gzip.NewReader(gf)
		if err != nil {
			log.Fatal(err.Error())
		}
		bytes, _ := io.ReadAll(hargo.NewReader(f))
		groupSize += len(bytes)
		log.Printf("Converting:\t%6d : %s %6dKB. Group%4d, size: %4dMB", i, gzfile.Name(), len(bytes)>>10, group, groupSize>>20)
		json.Unmarshal(bytes, &har)
		gf.Close()
		f.Close()
		archive.AppendHar(har)
		hostnames = append(hostnames, har.Log.Entries[0].Request.URL+","+gzfile.Name())
	}
}

func continueFromLog(logPath string) (int, int) {
	// e.g. if OOM occurs, the last 2 line will be like:
	// 2021/03/02 11:28:13 Saving group 60(157 files) 	 -- 10062/491484
	// signal: killed
	// We just need to find the last successfully saved group number and corresponding file number to restart program.
	// e.g. return: group = 59, fileNumber =  9905
	lines, err := readLines(logPath)
	var group, fileNumber int
	if err != nil {
		log.Fatalf("readLog: %s", err)
	}
	for i := len(lines) - 1; i >= 0; i-- {
		var s, e int
		if strings.Contains(lines[i], "Saving group") {
			if strings.Contains(lines[i+1], "signal: killed") {
				continue
			}
			// fmt.Printf("Detect Log: %s", lines[i])
			s = strings.Index(lines[i], "Saving group ")
			e = strings.Index(lines[i], "(")
			group, err = strconv.Atoi(lines[i][s+13 : e])
			if err != nil {
				log.Fatalf("readLog: %s", err)
			}
			group++

			s = strings.Index(lines[i], "-- ")
			e = strings.LastIndex(lines[i], "/")
			fileNumber, err = strconv.Atoi(lines[i][s+3 : e])
			if err != nil {
				log.Fatalf("readLog: %s", err)
			}
			return group, fileNumber
		}
	}
	log.Println("No continue point found.")
	return 0, 0
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

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
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
		var contentEncoding string
		if len(contentEncodings) != 1 {
			log.Printf("Multiple content_encoding: %s", strings.Join(contentEncodings, ","))
			contentEncoding = "gzip"
		} else {
			contentEncoding = contentEncodings[0]
		}
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
		case "identity", "none", "utf8", "UTF-8", "utf-8", "":
			w := bufio.NewWriter(&b)
			if _, err = w.Write([]byte(entry.Response.Content.Text)); err != nil {
				log.Fatal("EntryToResponse:" + err.Error())
			}
			w.Flush()
		default:
			log.Println("Missing Content-Encoding:  " + contentEncoding)
			// to identity
			rw.HeaderMap["Content-Encoding"] = []string{"identity"}
			w := bufio.NewWriter(&b)
			if _, err = w.Write([]byte(entry.Response.Content.Text)); err != nil {
				log.Fatal("EntryToResponse:" + err.Error())
			}
			w.Flush()
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
