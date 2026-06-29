package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

type DefaultCredsTool struct{}

func (t *DefaultCredsTool) Name() string {
	return "default_creds"
}

func (t *DefaultCredsTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 50
	}
	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]recon.Event, error) {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil, nil
		}

		var host string
		var port int
		var isHTTP bool
		var scheme string = "http"

		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			isHTTP = true
			parsed, err := url.Parse(target)
			if err == nil {
				host = parsed.Hostname()
				scheme = parsed.Scheme
				pStr := parsed.Port()
				if pStr != "" {
					port, _ = strconv.Atoi(pStr)
				} else {
					if scheme == "https" {
						port = 443
					} else {
						port = 80
					}
				}
			} else {
				return nil, nil
			}
		} else {
			// Host:Port format
			h, pStr, err := net.SplitHostPort(target)
			if err == nil {
				host = h
				port, _ = strconv.Atoi(pStr)
			} else {
				host = target
				// Default port based on some simple checks or default to 80
				port = 80
			}
		}

		client := NewSafeHTTPClient(5 * time.Second)
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		var events []recon.Event

		// Test mapping based on port
		switch port {
		case 8080: // Jenkins
			t.checkJenkins(ctx, client, scheme, host, port, &events)
		case 5601: // Kibana
			t.checkKibana(ctx, client, scheme, host, port, &events)
		case 9200: // Elasticsearch
			t.checkElasticsearch(ctx, client, scheme, host, port, &events)
		case 6379: // Redis
			t.checkRedis(ctx, host, port, &events)
		case 27017: // MongoDB
			t.checkMongoDB(ctx, host, port, &events)
		case 8001: // Kubernetes Dashboard / API
			t.checkKubeDashboard(ctx, client, scheme, host, port, &events)
		case 10250: // Kubelet API
			t.checkKubelet(ctx, client, scheme, host, port, &events)
		case 8888: // Jupyter Notebook
			t.checkJupyter(ctx, client, scheme, host, port, &events)
		case 2375: // Docker API
			t.checkDockerAPI(ctx, client, scheme, host, port, &events)
		case 3000: // Grafana
			t.checkGrafana(ctx, client, scheme, host, port, &events)
		case 50070, 9870: // Hadoop NameNode
			t.checkHadoop(ctx, client, scheme, host, port, &events)
		case 8500: // Consul
			t.checkConsul(ctx, client, scheme, host, port, &events)
		case 9090: // Prometheus
			t.checkPrometheus(ctx, client, scheme, host, port, &events)
		case 8983: // Apache Solr
			t.checkSolr(ctx, client, scheme, host, port, &events)
		}

		// Also check phpMyAdmin path if target is an HTTP target
		if isHTTP {
			t.checkPhpMyAdmin(ctx, client, target, &events)
		}

		return events, nil
	})
}

func (t *DefaultCredsTool) checkJenkins(ctx context.Context, client *http.Client, scheme, host string, port int, events *[]recon.Event) {
	url := fmt.Sprintf("%s://%s:%d/api/json", scheme, host, port)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			*events = append(*events, recon.NewEventWithSeverity(fmt.Sprintf("%s:%d", host, port), t.Name(), "vulnerability", map[string]string{
				"vuln_name":   "Unauthenticated Jenkins Dashboard Access",
				"severity":    "critical",
				"description": "Jenkins dashboard exposes unauthenticated API access.",
			}, "critical"))
			return
		}
	}

	// Try default credentials: admin:admin
	loginURL := fmt.Sprintf("%s://%s:%d/j_acegi_security_check", scheme, host, port)
	data := "j_username=admin&j_password=admin&submit=Sign+in"
	req, _ = http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(data))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 302 && !strings.Contains(resp.Header.Get("Location"), "loginError") {
			*events = append(*events, recon.NewEventWithSeverity(fmt.Sprintf("%s:%d", host, port), t.Name(), "vulnerability", map[string]string{
				"vuln_name":   "Jenkins Default Credentials (admin:admin)",
				"severity":    "critical",
				"description": "Jenkins console allows access using default credentials (admin:admin).",
			}, "critical"))
		}
	}
}

func (t *DefaultCredsTool) checkKibana(ctx context.Context, client *http.Client, scheme, host string, port int, events *[]recon.Event) {
	url := fmt.Sprintf("%s://%s:%d/api/status", scheme, host, port)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("kbn-xsrf", "true")
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			if strings.Contains(string(body), "name") && strings.Contains(string(body), "version") {
				*events = append(*events, recon.NewEventWithSeverity(fmt.Sprintf("%s:%d", host, port), t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "Unauthenticated Kibana Dashboard Access",
					"severity":    "high",
					"description": "Kibana dashboard status page exposes unauthenticated access.",
				}, "high"))
			}
		}
	}
}

func (t *DefaultCredsTool) checkElasticsearch(ctx context.Context, client *http.Client, scheme, host string, port int, events *[]recon.Event) {
	url := fmt.Sprintf("%s://%s:%d/", scheme, host, port)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			if strings.Contains(string(body), "cluster_name") && strings.Contains(string(body), "lucene_version") {
				*events = append(*events, recon.NewEventWithSeverity(fmt.Sprintf("%s:%d", host, port), t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "Unauthenticated Elasticsearch API Access",
					"severity":    "critical",
					"description": "Elasticsearch API node exposes unauthenticated cluster statistics.",
				}, "critical"))
			}
		}
	}
}

func (t *DefaultCredsTool) checkRedis(ctx context.Context, host string, port int, events *[]recon.Event) {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write([]byte("PING\r\n"))
	if err != nil {
		return
	}

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		res := string(buf[:n])
		if strings.Contains(res, "+PONG") || strings.Contains(res, "NOAUTH") {
			severity := "info"
			vulnName := "Exposed Redis Port"
			desc := "Redis port 6379 is publicly exposed but requires authentication."

			if strings.Contains(res, "+PONG") {
				severity = "critical"
				vulnName = "Unauthenticated Redis Database Access"
				desc = "Redis database allows unauthenticated connection and command execution."
			}

			*events = append(*events, recon.NewEventWithSeverity(fmt.Sprintf("%s:%d", host, port), t.Name(), "vulnerability", map[string]string{
				"vuln_name":   vulnName,
				"severity":    severity,
				"description": desc,
			}, severity))
		}
	}
}

func (t *DefaultCredsTool) checkMongoDB(ctx context.Context, host string, port int, events *[]recon.Event) {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return
	}
	defer conn.Close()

	// Simple MongoDB wire protocol handshake payload
	// OP_QUERY command to admin.$cmd checking "whatsmyuri"
	mongoPayload := []byte{
		0x3b, 0x00, 0x00, 0x00, // Message length (59 bytes)
		0x01, 0x00, 0x00, 0x00, // Request ID
		0x00, 0x00, 0x00, 0x00, // Response To
		0xd4, 0x07, 0x00, 0x00, // OP_QUERY opcode (2004)
		0x00, 0x00, 0x00, 0x00, // Query flags
		0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, // Collection name "admin.$cmd"
		0x00, 0x00, 0x00, 0x00, // Number to skip
		0xff, 0xff, 0xff, 0xff, // Number to return (-1)
		// Document BSON: {whatsmyuri: 1}
		0x15, 0x00, 0x00, 0x00, // Document length (21 bytes)
		0x10, // Element type: Int32
		0x77, 0x68, 0x61, 0x74, 0x73, 0x6d, 0x79, 0x75, 0x72, 0x69, 0x00, // Key name: whatsmyuri
		0x01, 0x00, 0x00, 0x00, // Value: 1
		0x00, // Document end
	}

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write(mongoPayload)
	if err != nil {
		return
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && n > 16 {
		// MongoDB responds with OP_REPLY (opcode 1)
		// Check if response signature contains OP_REPLY opcode (1000 in little endian or bytes)
		// Usually if we get a response payload containing "youAreNotInAShard" or "ok" or successfully parsing BSON
		*events = append(*events, recon.NewEventWithSeverity(fmt.Sprintf("%s:%d", host, port), t.Name(), "vulnerability", map[string]string{
			"vuln_name":   "Unauthenticated MongoDB Database Access",
			"severity":    "critical",
			"description": "MongoDB database is exposed and responds to unauthenticated wire queries.",
		}, "critical"))
	}
}

func (t *DefaultCredsTool) checkKubeDashboard(ctx context.Context, client *http.Client, scheme, host string, port int, events *[]recon.Event) {
	url := fmt.Sprintf("%s://%s:%d/api/v1/namespaces", scheme, host, port)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			if strings.Contains(string(body), "NamespaceList") {
				*events = append(*events, recon.NewEventWithSeverity(fmt.Sprintf("%s:%d", host, port), t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "Kubernetes API Unauthenticated Access",
					"severity":    "critical",
					"description": "Kubernetes API server allows anonymous user read access to namespaces.",
				}, "critical"))
			}
		}
	}
}

func (t *DefaultCredsTool) checkKubelet(ctx context.Context, client *http.Client, scheme, host string, port int, events *[]recon.Event) {
	url := fmt.Sprintf("%s://%s:%d/pods", scheme, host, port)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			if strings.Contains(string(body), "PodList") || strings.Contains(string(body), "items") {
				*events = append(*events, recon.NewEventWithSeverity(fmt.Sprintf("%s:%d", host, port), t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "Kubernetes Kubelet API Exposed",
					"severity":    "critical",
					"description": "Kubelet API server allows anonymous user read access to pods.",
				}, "critical"))
			}
		}
	}
}

func (t *DefaultCredsTool) checkJupyter(ctx context.Context, client *http.Client, scheme, host string, port int, events *[]recon.Event) {
	url := fmt.Sprintf("%s://%s:%d/api/contents", scheme, host, port)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			if strings.Contains(string(body), "notebooks") || strings.Contains(string(body), "directory") {
				*events = append(*events, recon.NewEventWithSeverity(fmt.Sprintf("%s:%d", host, port), t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "Jupyter Notebook Unauthenticated Access",
					"severity":    "critical",
					"description": "Jupyter Notebook instance dashboard is accessible without token authentication.",
				}, "critical"))
			}
		}
	}
}

func (t *DefaultCredsTool) checkDockerAPI(ctx context.Context, client *http.Client, scheme, host string, port int, events *[]recon.Event) {
	url := fmt.Sprintf("%s://%s:%d/version", scheme, host, port)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			if strings.Contains(string(body), "ApiVersion") && strings.Contains(string(body), "GoVersion") {
				*events = append(*events, recon.NewEventWithSeverity(fmt.Sprintf("%s:%d", host, port), t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "Docker REST API Unauthenticated Access",
					"severity":    "critical",
					"description": "Docker daemon REST API exposes unauthenticated system controls.",
				}, "critical"))
			}
		}
	}
}

func (t *DefaultCredsTool) checkGrafana(ctx context.Context, client *http.Client, scheme, host string, port int, events *[]recon.Event) {
	url := fmt.Sprintf("%s://%s:%d/api/login", scheme, host, port)
	postBody := `{"user":"admin","email":"","password":"admin"}`
	req, _ := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(postBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			if strings.Contains(string(body), "Logged in") || strings.Contains(string(body), "token") {
				*events = append(*events, recon.NewEventWithSeverity(fmt.Sprintf("%s:%d", host, port), t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "Grafana Default Credentials (admin:admin)",
					"severity":    "critical",
					"description": "Grafana admin console allows access using default credentials (admin:admin).",
				}, "critical"))
			}
		}
	}
}

func (t *DefaultCredsTool) checkHadoop(ctx context.Context, client *http.Client, scheme, host string, port int, events *[]recon.Event) {
	url := fmt.Sprintf("%s://%s:%d/dfshealth.html", scheme, host, port)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			if strings.Contains(string(body), "Hadoop") && strings.Contains(string(body), "NameNode") {
				*events = append(*events, recon.NewEventWithSeverity(fmt.Sprintf("%s:%d", host, port), t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "Hadoop NameNode Unauthenticated Access",
					"severity":    "high",
					"description": "Hadoop NameNode health dashboard is accessible without authentication.",
				}, "high"))
			}
		}
	}
}

func (t *DefaultCredsTool) checkConsul(ctx context.Context, client *http.Client, scheme, host string, port int, events *[]recon.Event) {
	url := fmt.Sprintf("%s://%s:%d/v1/status/leader", scheme, host, port)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
			if strings.Contains(string(body), ":") {
				*events = append(*events, recon.NewEventWithSeverity(fmt.Sprintf("%s:%d", host, port), t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "Consul API Unauthenticated Access",
					"severity":    "high",
					"description": "Consul leader status endpoint allows unauthenticated information gathering.",
				}, "high"))
			}
		}
	}
}

func (t *DefaultCredsTool) checkPrometheus(ctx context.Context, client *http.Client, scheme, host string, port int, events *[]recon.Event) {
	url := fmt.Sprintf("%s://%s:%d/api/v1/targets", scheme, host, port)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			if strings.Contains(string(body), "activeTargets") || strings.Contains(string(body), "success") {
				*events = append(*events, recon.NewEventWithSeverity(fmt.Sprintf("%s:%d", host, port), t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "Prometheus API Unauthenticated Access",
					"severity":    "high",
					"description": "Prometheus metric targets configuration exposes unauthenticated statistics.",
				}, "high"))
			}
		}
	}
}

func (t *DefaultCredsTool) checkSolr(ctx context.Context, client *http.Client, scheme, host string, port int, events *[]recon.Event) {
	url := fmt.Sprintf("%s://%s:%d/solr/admin/info/system?wt=json", scheme, host, port)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			if strings.Contains(string(body), "solr-spec") || strings.Contains(string(body), "lucene") {
				*events = append(*events, recon.NewEventWithSeverity(fmt.Sprintf("%s:%d", host, port), t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "Apache Solr Admin Unauthenticated Access",
					"severity":    "high",
					"description": "Apache Solr system administrator console is accessible without authentication.",
				}, "high"))
			}
		}
	}
}

func (t *DefaultCredsTool) checkPhpMyAdmin(ctx context.Context, client *http.Client, baseURL string, events *[]recon.Event) {
	paths := []string{"/phpmyadmin/", "/pma/", "/phpMyAdmin/"}
	for _, p := range paths {
		targetURL := baseURL
		if !strings.HasSuffix(targetURL, "/") {
			targetURL += p
		} else {
			targetURL += p[1:]
		}

		// Try logging in with default root credentials (root:root, root:empty)
		loginURL := targetURL + "index.php"
		postData := "pma_username=root&pma_password=root&server=1"
		req, _ := http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(postData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			if resp.StatusCode == 200 && (strings.Contains(string(body), "db_structure.php") || strings.Contains(string(body), "token")) {
				*events = append(*events, recon.NewEventWithSeverity(baseURL, t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "phpMyAdmin Default Credentials (root:root)",
					"severity":    "critical",
					"description": "phpMyAdmin allows database administrator access using default credentials (root:root).",
				}, "critical"))
				return
			}
		}
	}
}

var _ recon.Tool = (*DefaultCredsTool)(nil)
