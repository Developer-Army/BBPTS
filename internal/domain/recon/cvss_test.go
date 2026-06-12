package recon

import "testing"

func TestCVSS31BaseScore(t *testing.T) {
	tests := []struct {
		vector    string
		wantScore float64
		wantSev   string
	}{
		// CVE-2021-44228 (Log4j): CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "Critical"},
		// CVE-2020-0601 (Windows CryptoAPI): CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.4, "High"},
		// AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N
		{"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N", 3.8, "Low"},
	}

	for _, tt := range tests {
		cvss, err := ParseCVSS31(tt.vector)
		if err != nil {
			t.Fatalf("failed to parse vector %s: %v", tt.vector, err)
		}
		gotScore := cvss.BaseScore()
		if gotScore != tt.wantScore {
			t.Errorf("CVSS BaseScore(%q) = %v; want %v", tt.vector, gotScore, tt.wantScore)
		}
		gotSev := cvss.Severity()
		if gotSev != tt.wantSev {
			t.Errorf("CVSS Severity(%q) = %v; want %v", tt.vector, gotSev, tt.wantSev)
		}
	}
}
