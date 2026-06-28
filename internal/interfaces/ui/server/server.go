package server

import (
	"embed"
	"io"
	"strings"
	"sync"

	"github.com/Developer-Army/BBPTS/internal/domain/security"
)

//go:embed static/*
var staticFS embed.FS

// Config holds the web server configuration.
type Config struct {
	Port        int
	TLSEnabled  bool
	TLSCertFile string
	TLSKeyFile  string
}

// LogBroadcasterWriter multiplexes logs to original writer and dashboard clients.
type LogBroadcasterWriter struct {
	Original io.Writer
}

func (lw *LogBroadcasterWriter) Write(p []byte) (n int, err error) {
	redactedStr := security.RedactSecrets(string(p))
	redactedBytes := []byte(redactedStr)
	_, err = lw.Original.Write(redactedBytes)
	BroadcastLog(redactedStr)
	return len(p), err
}

var (
	logMu      sync.RWMutex
	logClients = make(map[chan string]bool)
)

func RegisterLogClient(c chan string) {
	logMu.Lock()
	defer logMu.Unlock()
	logClients[c] = true
}

func UnregisterLogClient(c chan string) {
	logMu.Lock()
	defer logMu.Unlock()
	delete(logClients, c)
}

func BroadcastLog(msg string) {
	logMu.RLock()
	defer logMu.RUnlock()
	for c := range logClients {
		select {
		case c <- msg:
		default:
		}
	}
}

//go:embed frontend/*
var frontendFS embed.FS

// DashboardHTML is the embedded frontend for the BBPTS elite dashboard.
var DashboardHTML string

func init() {
	htmlBytes, err := frontendFS.ReadFile("frontend/index.html")
	if err != nil {
		panic(err)
	}
	cssBytes, err := frontendFS.ReadFile("frontend/style.css")
	if err != nil {
		panic(err)
	}
	jsBytes, err := frontendFS.ReadFile("frontend/app.js")
	if err != nil {
		panic(err)
	}

	html := string(htmlBytes)
	html = strings.Replace(html, "<link rel=\"stylesheet\" href=\"/style.css\">", "<style>"+string(cssBytes)+"</style>", 1)
	html = strings.Replace(html, "<script src=\"/app.js\"></script>", "<script>"+string(jsBytes)+"</script>", 1)
	DashboardHTML = html
}
