package worker

// Minimal chunked parser used by the spec_fuzz worker tests to
// simulate a target adapter without a subprocess.

//nolint:gocognit,gocyclo // test-only reference parser
func parseChunkedH11(buf []byte, strict bool) ([]byte, bool) {
	hexv := func(b byte) int {
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
	var body []byte
	i := 0
	for {
		start := i
		for i < len(buf) && hexv(buf[i]) >= 0 {
			i++
		}
		if i == start || i-start > 15 {
			return nil, false
		}
		size := 0
		for _, c := range buf[start:i] {
			size = size*16 + hexv(c)
		}
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
			for {
				if i+1 < len(buf) && buf[i] == '\r' && buf[i+1] == '\n' {
					return body, i+2 == len(buf)
				}
				j, colon := i, false
				for j < len(buf) && buf[j] != '\r' {
					if buf[j] == '\n' {
						return nil, false
					}
					if buf[j] == ':' {
						colon = true
					}
					j++
				}
				if !colon || j+1 >= len(buf) || buf[j+1] != '\n' {
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
		if strict {
			if i+1 >= len(buf) || buf[i] != '\r' || buf[i+1] != '\n' {
				return nil, false
			}
		} else if i+1 >= len(buf) {
			return nil, false
		}
		i += 2
	}
}
