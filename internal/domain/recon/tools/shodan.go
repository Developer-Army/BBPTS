package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/bits"
	"net/http"
	"strings"
	"time"
)

type ShodanTool struct{}

type shodanResult struct {
	IP       string `json:"ip_str"`
	Port     int    `json:"port"`
	Protocol string `json:"_shodan.module"`
	Product  string `json:"product"`
	Version  string `json:"version"`
	Title    string `json:"title"`
	Banner   string `json:"data"`
	Org      string `json:"org"`
	ISP      string `json:"isp"`
	Country  string `json:"country_name"`
}

type shodanResponse struct {
	Matches []shodanResult `json:"matches"`
	Total   int            `json:"total"`
}

func (t *ShodanTool) Name() string {
	return "shodan"
}

func (t *ShodanTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	apiKey := scanCtx.APIKeys["shodan"]
	if apiKey == "" {
		slog.Debug("Shodan API key not configured, skipping")
		return nil, nil
	}

	events := make([]recon.Event, 0)
	client := NewSafeRateLimitedClient(10*time.Second, 1000, 30000)

	for i, target := range targets {
		select {
		case <-ctx.Done():
			return events, ctx.Err()
		default:
		}

		host := strings.TrimSpace(target)
		if idx := strings.Index(host, "://"); idx != -1 {
			host = host[idx+3:]
		}
		if idx := strings.Index(host, "/"); idx != -1 {
			host = host[:idx]
		}
		if idx := strings.Index(host, ":"); idx != -1 {
			host = host[:idx]
		}
		if host == "" {
			continue
		}

		if i > 0 {
			// Rate limit: Shodan API allows 1 query per second on basic/academic plans
			select {
			case <-ctx.Done():
				return events, ctx.Err()
			case <-time.After(1 * time.Second):
			}
		}

		qg := scanCtx.QuotaGuard
		if qg != nil {
			qg.Increment("shodan")
		}

		// 1. Standard host search
		url := fmt.Sprintf("https://api.shodan.io/shodan/host/search?query=%s&key=%s&limit=10", host, apiKey)
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err == nil {
			headers := scanCtx.Headers
			for k, v := range headers {
				req.Header.Set(k, v)
			}

			resp, errResp := client.Do(ctx, req)
			if errResp == nil {
				defer resp.Body.Close()
				if resp.StatusCode == 200 {
					var shodanResp shodanResponse
					if errDec := json.NewDecoder(io.LimitReader(resp.Body, 10*1024*1024)).Decode(&shodanResp); errDec == nil {
						for _, match := range shodanResp.Matches {
							matchTarget := fmt.Sprintf("%s:%d", match.IP, match.Port)
							props := map[string]string{
								"protocol": match.Protocol,
								"product":  match.Product,
								"version":  match.Version,
								"title":    match.Title,
								"org":      match.Org,
								"country":  match.Country,
							}
							if match.ISP != "" {
								props["isp"] = match.ISP
							}
							events = append(events, recon.NewEvent(matchTarget, t.Name(), "service", props))
						}
					}
				} else {
					_, _ = io.Copy(io.Discard, resp.Body)
				}
			}
		}

		// 2. Favicon hash discovery and correlation
		if hash, errFav := fetchFaviconAndHash(ctx, target); errFav == nil {
			slog.Info("Fetched favicon and calculated hash", "target", target, "hash", hash)
			favQuery := fmt.Sprintf("http.favicon.hash:%d", hash)
			urlFav := fmt.Sprintf("https://api.shodan.io/shodan/host/search?query=%s&key=%s&limit=50", favQuery, apiKey)

			if qg != nil {
				qg.Increment("shodan")
			}

			reqFav, errReq := http.NewRequestWithContext(ctx, "GET", urlFav, nil)
			if errReq == nil {
				respFav, errResp := client.Do(ctx, reqFav)
				if errResp == nil {
					defer respFav.Body.Close()
					if respFav.StatusCode == 200 {
						var shodanResp shodanResponse
						if errDec := json.NewDecoder(io.LimitReader(respFav.Body, 10*1024*1024)).Decode(&shodanResp); errDec == nil {
							slog.Info("Discovered assets via Shodan favicon correlation", "hash", hash, "count", len(shodanResp.Matches))
							for _, match := range shodanResp.Matches {
								matchTarget := fmt.Sprintf("%s:%d", match.IP, match.Port)
								props := map[string]string{
									"protocol":     match.Protocol,
									"product":      match.Product,
									"version":      match.Version,
									"title":        match.Title,
									"org":          match.Org,
									"country":      match.Country,
									"favicon_hash": fmt.Sprintf("%d", hash),
								}
								if match.ISP != "" {
									props["isp"] = match.ISP
								}
								events = append(events, recon.NewEvent(matchTarget, t.Name(), "service", props))
							}
						}
					} else {
						_, _ = io.Copy(io.Discard, respFav.Body)
					}
				}
			}
		}
	}

	return events, nil
}

func fetchFaviconAndHash(ctx context.Context, target string) (int32, error) {
	urlStr := target
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "https://" + urlStr
	}

	favURL := urlStr
	if !strings.HasSuffix(favURL, "/") {
		favURL += "/"
	}
	favURL += "favicon.ico"

	req, err := http.NewRequestWithContext(ctx, "GET", favURL, nil)
	if err != nil {
		return 0, err
	}

	client := NewSafeHTTPClient(5 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		if strings.HasPrefix(favURL, "https://") {
			favURL = "http://" + strings.TrimPrefix(favURL, "https://")
			req, err = http.NewRequestWithContext(ctx, "GET", favURL, nil)
			if err == nil {
				resp, err = client.Do(req)
			}
		}
	}

	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("status code %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return 0, err
	}

	if len(data) == 0 {
		return 0, fmt.Errorf("empty favicon body")
	}

	return calculateFaviconHash(data), nil
}

func calculateFaviconHash(data []byte) int32 {
	b64 := base64.StdEncoding.EncodeToString(data)

	var formatted strings.Builder
	for i := 0; i < len(b64); i++ {
		formatted.WriteByte(b64[i])
		if (i+1)%76 == 0 {
			formatted.WriteByte('\n')
		}
	}
	if len(b64)%76 != 0 {
		formatted.WriteByte('\n')
	}

	return murmur332([]byte(formatted.String()))
}

func murmur332(key []byte) int32 {
	var h1 uint32 = 0
	const (
		c1 uint32 = 0xcc9e2d51
		c2 uint32 = 0x1b873593
	)

	nblocks := len(key) / 4
	for i := 0; i < nblocks; i++ {
		k1 := uint32(key[i*4]) |
			uint32(key[i*4+1])<<8 |
			uint32(key[i*4+2])<<16 |
			uint32(key[i*4+3])<<24

		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2

		h1 ^= k1
		h1 = bits.RotateLeft32(h1, 13)
		h1 = h1*5 + 0xe6546b64
	}

	tail := key[nblocks*4:]
	var k1 uint32 = 0
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2
		h1 ^= k1
	}

	h1 ^= uint32(len(key))
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16

	return int32(h1)
}
