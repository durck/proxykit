package detect

// mergeWinHTTPSources combines the WinHTTP proxy + PAC sources into
// de-duplicated candidates tagged "winhttp": the HKLM "Internet Settings"
// hive (hklm proxy + hklmPAC AutoConfigURL, with hklmErr from the proxy
// read) and the current user's IE config (ieProxy + iePAC
// lpszAutoConfigURL). Proxy candidates carry URL; PAC candidates carry
// PACURL. Proxy and PAC URLs are de-duplicated within their own kind.
//
// The sources are independent: an HKLM read error must not discard an IE
// candidate, so the error is surfaced only when nothing at all was found —
// otherwise detect.All would drop the other candidates alongside the error
// (it skips a detector's candidates whenever it returns non-nil).
//
// Kept platform-agnostic so it is tested on every CI matrix entry without
// a real registry or WinHTTP API.
func mergeWinHTTPSources(hklm string, hklmErr error, ieProxy, hklmPAC, iePAC string) ([]Candidate, error) {
	var out []Candidate
	seen := map[string]struct{}{}

	addProxy := func(rawURL string) {
		if rawURL == "" {
			return
		}
		if _, dup := seen["proxy:"+rawURL]; dup {
			return
		}
		seen["proxy:"+rawURL] = struct{}{}
		out = append(out, Candidate{URL: rawURL, From: "winhttp"})
	}
	addPAC := func(pacURL string) {
		if pacURL == "" {
			return
		}
		if _, dup := seen["pac:"+pacURL]; dup {
			return
		}
		seen["pac:"+pacURL] = struct{}{}
		out = append(out, Candidate{PACURL: pacURL, From: "winhttp"})
	}

	addProxy(hklm)
	addProxy(ieProxy)
	addPAC(hklmPAC)
	addPAC(iePAC)

	if len(out) == 0 && hklmErr != nil {
		return nil, hklmErr
	}
	return out, nil
}
