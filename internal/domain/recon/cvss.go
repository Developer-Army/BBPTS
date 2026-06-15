package recon

import (
	"fmt"
	"math"
	"strings"
)

// CVSS31 represents a CVSS v3.1 score calculator.
type CVSS31 struct {
	AttackVector       string // AV: N, A, L, P
	AttackComplexity   string // AC: L, H
	PrivilegesRequired string // PR: N, L, H
	UserInteraction    string // UI: N, R
	Scope              string // S: U, C
	Confidentiality    string // C: N, L, H
	Integrity          string // I: N, L, H
	Availability       string // A: N, L, H
}

// Vector returns the CVSS v3.1 vector string.
func (c CVSS31) Vector() string {
	return fmt.Sprintf("CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s",
		c.AttackVector, c.AttackComplexity, c.PrivilegesRequired, c.UserInteraction,
		c.Scope, c.Confidentiality, c.Integrity, c.Availability)
}

// BaseScore calculates the CVSS v3.1 base score.
func (c CVSS31) BaseScore() float64 {
	var av, ac, pr, ui, conf, intg, avail float64

	switch c.AttackVector {
	case "N":
		av = 0.85
	case "A":
		av = 0.62
	case "L":
		av = 0.55
	case "P":
		av = 0.20
	default:
		av = 0.85
	}

	switch c.AttackComplexity {
	case "L":
		ac = 0.77
	case "H":
		ac = 0.44
	default:
		ac = 0.77
	}

	switch c.PrivilegesRequired {
	case "N":
		pr = 0.85
	case "L":
		if c.Scope == "C" {
			pr = 0.68
		} else {
			pr = 0.62
		}
	case "H":
		if c.Scope == "C" {
			pr = 0.50
		} else {
			pr = 0.27
		}
	default:
		pr = 0.85
	}

	switch c.UserInteraction {
	case "N":
		ui = 0.85
	case "R":
		ui = 0.62
	default:
		ui = 0.85
	}

	switch c.Confidentiality {
	case "N":
		conf = 0.0
	case "L":
		conf = 0.22
	case "H":
		conf = 0.56
	default:
		conf = 0.0
	}

	switch c.Integrity {
	case "N":
		intg = 0.0
	case "L":
		intg = 0.22
	case "H":
		intg = 0.56
	default:
		intg = 0.0
	}

	switch c.Availability {
	case "N":
		avail = 0.0
	case "L":
		avail = 0.22
	case "H":
		avail = 0.56
	default:
		avail = 0.0
	}

	iss := 1.0 - ((1.0 - conf) * (1.0 - intg) * (1.0 - avail))

	var impact float64
	if c.Scope == "C" {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.029, 15.0)
	} else {
		impact = 6.42 * iss
	}

	exploitability := 8.22 * av * ac * pr * ui

	if iss <= 0 {
		return 0.0
	}

	if c.Scope == "C" {
		return roundup(math.Min(1.08*(impact+exploitability), 10.0))
	}
	return roundup(math.Min(impact+exploitability, 10.0))
}

func roundup(val float64) float64 {
	intVal := math.Round(val * 100000)
	if math.Mod(intVal, 10000) == 0 {
		return float64(int(intVal/10000)) / 10.0
	}
	return math.Ceil(val*10.0) / 10.0
}

// Severity returns the CVSS v3.1 severity rating.
func (c CVSS31) Severity() string {
	score := c.BaseScore()
	if score <= 0.0 {
		return "None"
	}
	if score <= 3.9 {
		return "Low"
	}
	if score <= 6.9 {
		return "Medium"
	}
	if score <= 8.9 {
		return "High"
	}
	return "Critical"
}

// ParseCVSS31 parses a CVSS v3.1 vector string.
func ParseCVSS31(vector string) (CVSS31, error) {
	c := CVSS31{
		AttackVector:       "N",
		AttackComplexity:   "L",
		PrivilegesRequired: "N",
		UserInteraction:    "N",
		Scope:              "U",
		Confidentiality:    "N",
		Integrity:          "N",
		Availability:       "N",
	}

	parts := strings.Split(vector, "/")
	for _, p := range parts {
		kv := strings.Split(p, ":")
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "AV":
			c.AttackVector = kv[1]
		case "AC":
			c.AttackComplexity = kv[1]
		case "PR":
			c.PrivilegesRequired = kv[1]
		case "UI":
			c.UserInteraction = kv[1]
		case "S":
			c.Scope = kv[1]
		case "C":
			c.Confidentiality = kv[1]
		case "I":
			c.Integrity = kv[1]
		case "A":
			c.Availability = kv[1]
		}
	}
	return c, nil
}
