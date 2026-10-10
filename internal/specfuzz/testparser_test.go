package specfuzz

import (
	"bufio"
	"io"
)

// Minimal chunked-body parsers used only by the test adapters.

func newLineScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	return sc
}

func hexval(b byte) int {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0')
	case b >= 'a' && b <= 'f':
		return int(b - 'a' + 10)
	case b >= 'A' && b <= 'F':
		return int(b - 'A' + 10)
	}
	return -1
}

// parseChunkedLenient mimics h11 0.15.0: after chunk-data, blindly
// discard two bytes without checking they are CRLF.
func parseChunkedLenient(buf []byte) ([]byte, bool) {
	return parseChunked(buf, false)
}

// parseChunkedStrict requires CRLF after chunk-data.
func parseChunkedStrict(buf []byte) ([]byte, bool) {
	return parseChunked(buf, true)
}

//nolint:gocognit,gocyclo // test-only reference parser
func parseChunked(buf []byte, strict bool) ([]byte, bool) {
	var body []byte
	i := 0
	for {
		// chunk-size
		start := i
		for i < len(buf) && hexval(buf[i]) >= 0 {
			i++
		}
		if i == start || i-start > 15 {
			return nil, false
		}
		size := 0
		for _, c := range buf[start:i] {
			size = size*16 + hexval(c)
		}
		// chunk-ext: strict requires ';' or CR next; lenient allows
		// anything (h11 0.15.0 behaviour).
		if strict && i < len(buf) && buf[i] != '\r' && buf[i] != ';' {
			return nil, false
		}
		for i < len(buf) && buf[i] != '\r' {
			if buf[i] == '\n' {
				return nil, false
			}
			i++
		}
		if i+1 >= len(buf) || buf[i] != '\r' || buf[i+1] != '\n' {
			return nil, false
		}
		i += 2
		if size == 0 {
			// trailer-section then final CRLF
			for {
				if i+1 < len(buf) && buf[i] == '\r' && buf[i+1] == '\n' {
					return body, i+2 == len(buf)
				}
				j := i
				sawColon := false
				for j < len(buf) && buf[j] != '\r' {
					if buf[j] == '\n' {
						return nil, false
					}
					if buf[j] == ':' {
						sawColon = true
					}
					j++
				}
				if !sawColon || j+1 >= len(buf) || buf[j+1] != '\n' {
					return nil, false
				}
				i = j + 2
			}
		}
		if i+size > len(buf) {
			return nil, false
		}
		body = append(body, buf[i:i+size]...)
		i += size
		// terminator after chunk-data
		if strict {
			if i+1 >= len(buf) || buf[i] != '\r' || buf[i+1] != '\n' {
				return nil, false
			}
		} else {
			if i+1 >= len(buf) {
				return nil, false
			}
		}
		i += 2
	}
}
