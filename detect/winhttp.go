package detect

// mergeWinHTTPSources combines the two WinHTTP proxy sources — the HKLM
// "Internet Settings" hive (hklm, with hklmErr from the registry read)
// and the current user's IE config (ie) — into de-duplicated candidates
// tagged "winhttp".
//
// The sources are independent: an HKLM read error must not discard an IE
// candidate, so the error is surfaced only when neither source yielded a
// URL — otherwise detect.All would drop the IE candidate alongside the
// error (it skips a detector's candidates whenever it returns non-nil).
//
// Kept platform-agnostic so it is tested on every CI matrix entry without
// a real registry or WinHTTP API.
func mergeWinHTTPSources(hklm string, hklmErr error, ie string) ([]Candidate, error) {
	var out []Candidate
	seen := map[string]struct{}{}

	add := func(rawURL string) {
		if rawURL == "" {
			return
		}
		if _, dup := seen[rawURL]; dup {
			return
		}
		seen[rawURL] = struct{}{}
		out = append(out, Candidate{URL: rawURL, From: "winhttp"})
	}

	add(hklm)
	add(ie)

	if len(out) == 0 && hklmErr != nil {
		return nil, hklmErr
	}
	return out, nil
}
