package services

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type ProgramProfile struct {
	Handle         string   `json:"program_handle"`
	Platform       string   `json:"program_platform"`
	Name           string   `json:"program_name"`
	OfferBounty    bool     `json:"offer_bounty"`
	InScope        []string `json:"in_scope"`
	OutOfScope     []string `json:"out_of_scope"`
	BountyTargets  []string `json:"bounty_targets"`
	FailOn         string   `json:"fail_on"`
	SeverityCalc   []string `json:"severity_calculation_methods"`
	SubmitPlatform string   `json:"submit_platform"`
}

type ProgramLoaderConfig struct {
	H1Username string
	H1Token    string
	BCToken    string
}

type ProgramLoader struct {
	cfg    ProgramLoaderConfig
	client *http.Client
	h1Base string
	bcBase string
}

func NewProgramLoader(cfg ProgramLoaderConfig) *ProgramLoader {
	return &ProgramLoader{
		cfg:    cfg,
		client: &http.Client{Timeout: 15 * time.Second},
		h1Base: "https://api.hackerone.com/v1/hackers",
		bcBase: "https://api.bugcrowd.com",
	}
}

func (pl *ProgramLoader) shouldRefresh(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return true
	}
	return time.Since(info.ModTime()) > 1*time.Hour
}

func (pl *ProgramLoader) Load(handle string, refresh bool) (*ProgramProfile, error) {
	platform, cleanHandle, err := parseHandle(handle)
	if err != nil {
		return nil, err
	}

	configPath := fmt.Sprintf("configs/program_%s.json", cleanHandle)
	scopePath := fmt.Sprintf("configs/scope_%s.txt", cleanHandle)
	targetsPath := fmt.Sprintf("configs/targets_%s.txt", cleanHandle)

	if !refresh && !pl.shouldRefresh(configPath) && !pl.shouldRefresh(scopePath) && !pl.shouldRefresh(targetsPath) {
		data, err := os.ReadFile(configPath)
		if err == nil {
			var profile ProgramProfile
			if err := json.Unmarshal(data, &profile); err == nil {
				slog.Info("[program-loader] loaded cached program profile", "handle", cleanHandle)
				return &profile, nil
			}
		}
	}

	var profile *ProgramProfile
	switch platform {
	case "h1":
		profile, err = pl.fetchHackerOne(cleanHandle)
	case "bc":
		profile, err = pl.fetchBugcrowd(cleanHandle)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", platform)
	}

	if err != nil {
		return nil, err
	}

	profile.FailOn = "medium"
	profile.SeverityCalc = []string{"cvss_4_0"}
	profile.SubmitPlatform = platform

	return profile, nil
}

func parseHandle(handle string) (string, string, error) {
	if strings.Contains(handle, ":") {
		parts := strings.SplitN(handle, ":", 2)
		platform := strings.ToLower(parts[0])
		if platform != "h1" && platform != "bc" {
			return "", "", fmt.Errorf("invalid platform prefix: %s", parts[0])
		}
		return platform, parts[1], nil
	}
	return "", "", fmt.Errorf("invalid handle format, must be prefixed (e.g. h1:handle or bc:handle)")
}

func (pl *ProgramLoader) fetchHackerOne(handle string) (*ProgramProfile, error) {
	if pl.cfg.H1Username == "" || pl.cfg.H1Token == "" {
		return nil, fmt.Errorf("hackerone api username or token is missing")
	}

	progUrl := fmt.Sprintf("%s/programs/%s", pl.h1Base, handle)
	req, err := http.NewRequest("GET", progUrl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(pl.cfg.H1Username, pl.cfg.H1Token)

	resp, err := pl.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hackerone api program request returned status %d", resp.StatusCode)
	}

	var progResp struct {
		Data struct {
			Attributes struct {
				Name           string `json:"name"`
				OffersBounties bool   `json:"offers_bounties"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&progResp); err != nil {
		return nil, err
	}

	var inScope []string
	var outOfScope []string
	var bountyTargets []string

	scopeUrl := fmt.Sprintf("%s/programs/%s/structured_scopes", pl.h1Base, handle)
	for scopeUrl != "" {
		req, err := http.NewRequest("GET", scopeUrl, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.SetBasicAuth(pl.cfg.H1Username, pl.cfg.H1Token)

		resp, err := pl.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("hackerone api structured scopes request returned status %d", resp.StatusCode)
		}

		var scopeResp struct {
			Data []struct {
				Attributes struct {
					AssetIdentifier       string `json:"asset_identifier"`
					AssetType             string `json:"asset_type"`
					EligibleForBounty     bool   `json:"eligible_for_bounty"`
					EligibleForSubmission bool   `json:"eligible_for_submission"`
				} `json:"attributes"`
			} `json:"data"`
			Links struct {
				Next string `json:"next"`
			} `json:"links"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&scopeResp); err != nil {
			return nil, err
		}

		for _, item := range scopeResp.Data {
			assetType := strings.ToUpper(item.Attributes.AssetType)
			if assetType == "APPLE_APP_STORE" || assetType == "GOOGLE_PLAY_STORE" || assetType == "OTHER" {
				continue
			}

			cleanName := cleanTargetName(item.Attributes.AssetIdentifier)
			if cleanName == "" {
				continue
			}

			if item.Attributes.EligibleForSubmission {
				inScope = append(inScope, cleanName)
				if item.Attributes.EligibleForBounty {
					bountyTargets = append(bountyTargets, cleanName)
				}
			} else {
				outOfScope = append(outOfScope, cleanName)
			}
		}

		scopeUrl = scopeResp.Links.Next
	}

	return &ProgramProfile{
		Handle:         handle,
		Platform:       "hackerone",
		Name:           progResp.Data.Attributes.Name,
		OfferBounty:    progResp.Data.Attributes.OffersBounties,
		InScope:        uniqueStrings(inScope),
		OutOfScope:     uniqueStrings(outOfScope),
		BountyTargets:  uniqueStrings(bountyTargets),
		FailOn:         "medium",
		SeverityCalc:   []string{"cvss_4_0"},
		SubmitPlatform: "hackerone",
	}, nil
}

type BugcrowdResponse struct {
	Data     interface{}   `json:"data"`
	Included []RawResource `json:"included"`
}

type RawResource struct {
	ID            string                 `json:"id"`
	Type          string                 `json:"type"`
	Attributes    map[string]interface{} `json:"attributes"`
	Relationships map[string]RawRelation `json:"relationships"`
}

type RawRelation struct {
	Data json.RawMessage `json:"data"`
}

func (pl *ProgramLoader) fetchBugcrowd(handle string) (*ProgramProfile, error) {
	if pl.cfg.BCToken == "" {
		return nil, fmt.Errorf("bugcrowd api token is missing")
	}

	urlStr := fmt.Sprintf("%s/programs?include=current_brief.target_groups.targets", pl.bcBase)
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.bugcrowd+json")
	req.Header.Set("Authorization", "Token "+pl.cfg.BCToken)

	resp, err := pl.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bugcrowd api returned status %d", resp.StatusCode)
	}

	var bcResp BugcrowdResponse
	if err := json.NewDecoder(resp.Body).Decode(&bcResp); err != nil {
		return nil, err
	}

	dataBytes, err := json.Marshal(bcResp.Data)
	if err != nil {
		return nil, err
	}

	var programs []RawResource
	if err := json.Unmarshal(dataBytes, &programs); err != nil {
		var singleProgram RawResource
		if err := json.Unmarshal(dataBytes, &singleProgram); err != nil {
			return nil, fmt.Errorf("failed to parse program data: %w", err)
		}
		programs = []RawResource{singleProgram}
	}

	var matchedProg *RawResource
	for _, prog := range programs {
		code, _ := prog.Attributes["code"].(string)
		teaserCode, _ := prog.Attributes["teaser_code"].(string)
		if strings.EqualFold(code, handle) || strings.EqualFold(teaserCode, handle) || strings.EqualFold(prog.ID, handle) {
			matchedProg = &prog
			break
		}
	}

	if matchedProg == nil {
		return nil, fmt.Errorf("bugcrowd program %s not found in programs list", handle)
	}

	offerBounty := true
	if val, ok := matchedProg.Attributes["offers_bounty"]; ok {
		if b, ok := val.(bool); ok {
			offerBounty = b
		}
	}

	name, _ := matchedProg.Attributes["name"].(string)
	if name == "" {
		name = handle
	}

	var briefID string
	if cb, ok := matchedProg.Relationships["current_brief"]; ok {
		var cbData struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		}
		if err := json.Unmarshal(cb.Data, &cbData); err == nil {
			briefID = cbData.ID
		}
	}

	if briefID == "" {
		return nil, fmt.Errorf("current_brief relationship not found for program %s", handle)
	}

	var targetGroupIDs []string
	for _, inc := range bcResp.Included {
		if inc.Type == "program_brief" && inc.ID == briefID {
			if tgRel, ok := inc.Relationships["target_groups"]; ok {
				var tgList []struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				}
				if err := json.Unmarshal(tgRel.Data, &tgList); err == nil {
					for _, item := range tgList {
						targetGroupIDs = append(targetGroupIDs, item.ID)
					}
				}
			}
		}
	}

	type groupInfo struct {
		inScope   bool
		bounty    bool
		targetIDs []string
	}
	groupMap := make(map[string]groupInfo)

	for _, inc := range bcResp.Included {
		if inc.Type == "target_group" {
			inBrief := false
			for _, tgID := range targetGroupIDs {
				if inc.ID == tgID {
					inBrief = true
					break
				}
			}
			if !inBrief {
				continue
			}

			inScope := true
			if val, ok := inc.Attributes["in_scope"]; ok {
				if b, ok := val.(bool); ok {
					inScope = b
				}
			}

			bounty := offerBounty
			if val, ok := inc.Attributes["bounty"]; ok {
				if b, ok := val.(bool); ok {
					bounty = b
				}
			} else if val, ok := inc.Attributes["reward"]; ok {
				if b, ok := val.(bool); ok {
					bounty = b
				}
			}

			var targetIDs []string
			if tRel, ok := inc.Relationships["targets"]; ok {
				var tList []struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				}
				if err := json.Unmarshal(tRel.Data, &tList); err == nil {
					for _, item := range tList {
						targetIDs = append(targetIDs, item.ID)
					}
				}
			}

			groupMap[inc.ID] = groupInfo{
				inScope:   inScope,
				bounty:    bounty,
				targetIDs: targetIDs,
			}
		}
	}

	var inScope []string
	var outOfScope []string
	var bountyTargets []string

	for _, inc := range bcResp.Included {
		if inc.Type == "target" {
			var info groupInfo
			found := false
			for _, gInfo := range groupMap {
				for _, tID := range gInfo.targetIDs {
					if inc.ID == tID {
						info = gInfo
						found = true
						break
					}
				}
				if found {
					break
				}
			}

			if !found {
				continue
			}

			targetName := cleanTargetName(getTargetName(inc))
			if targetName == "" {
				continue
			}

			category, _ := inc.Attributes["category"].(string)
			category = strings.ToLower(category)
			if category == "hardware" {
				continue
			}

			if info.inScope {
				inScope = append(inScope, targetName)
				if info.bounty {
					bountyTargets = append(bountyTargets, targetName)
				}
			} else {
				outOfScope = append(outOfScope, targetName)
			}
		}
	}

	return &ProgramProfile{
		Handle:         handle,
		Platform:       "bugcrowd",
		Name:           name,
		OfferBounty:    offerBounty,
		InScope:        uniqueStrings(inScope),
		OutOfScope:     uniqueStrings(outOfScope),
		BountyTargets:  uniqueStrings(bountyTargets),
		FailOn:         "medium",
		SeverityCalc:   []string{"cvss_4_0"},
		SubmitPlatform: "bugcrowd",
	}, nil
}

func getTargetName(inc RawResource) string {
	if val, ok := inc.Attributes["name"]; ok {
		if s, ok := val.(string); ok && s != "" {
			return s
		}
	}
	if val, ok := inc.Attributes["uri"]; ok {
		if s, ok := val.(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func cleanTargetName(name string) string {
	name = strings.TrimSpace(name)
	if strings.Contains(name, "://") {
		if u, err := url.Parse(name); err == nil {
			host := u.Host
			if idx := strings.Index(host, ":"); idx != -1 {
				host = host[:idx]
			}
			return host
		}
	}
	if strings.Contains(name, "/") {
		isCIDR := false
		parts := strings.Split(name, "/")
		if len(parts) == 2 {
			if _, err := strconv.Atoi(parts[1]); err == nil {
				isCIDR = true
			}
		}
		if !isCIDR {
			name = parts[0]
		}
	}
	if idx := strings.Index(name, ":"); idx != -1 {
		if strings.Count(name, ":") == 1 {
			name = name[:idx]
		}
	}
	return name
}

func uniqueStrings(slice []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func (p *ProgramProfile) WriteScopeFile(path string) error {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# BBPTS scope file — %s (%s)\n", p.Name, p.Platform))
	sb.WriteString(fmt.Sprintf("# Fetched: %s\n\n", time.Now().UTC().Format(time.RFC3339)))

	sb.WriteString("# --- IN SCOPE ---\n")
	for _, item := range p.InScope {
		sb.WriteString(item)
		sb.WriteString("\n")
	}
	sb.WriteString("\n# --- OUT OF SCOPE ---\n")
	for _, item := range p.OutOfScope {
		if strings.HasPrefix(item, "!") {
			sb.WriteString(item)
			sb.WriteString("\n")
		} else {
			sb.WriteString("!")
			sb.WriteString(item)
			sb.WriteString("\n")
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(sb.String()), 0644)
}

func (p *ProgramProfile) WriteTargetsFile(path string) error {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Targets: %s — %s\n", p.Handle, p.Platform))
	for _, item := range p.BountyTargets {
		sb.WriteString(item)
		sb.WriteString("\n")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(sb.String()), 0644)
}

func (p *ProgramProfile) WriteConfigPatch(path string) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
