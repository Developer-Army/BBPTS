package server

import (
	"log/slog"
	"net/http"
)

func RegisterRoutes(mux *http.ServeMux, api *API) {

	mux.Handle("/static/", http.FileServer(http.FS(staticFS)))

	mux.HandleFunc("/api/auth", api.Authenticate)
	mux.HandleFunc("/api/logout", api.Logout)
	mux.HandleFunc("/api/me", api.GetCurrentUser)
	mux.HandleFunc("/api/stats", api.GetStats)
	mux.HandleFunc("/api/scans", api.GetScans)
	mux.HandleFunc("/api/events", api.GetEvents)
	mux.HandleFunc("/api/config", api.HandleConfig)
	mux.HandleFunc("/api/logs/stream", api.StreamLogs)
	mux.HandleFunc("/api/fleet/sync", api.HandleFleetSync)
	mux.HandleFunc("/api/setup-token", api.GetSetupToken)
	mux.HandleFunc("/api/enroll", api.EnrollAdmin)
	mux.HandleFunc("/api/history/risk", api.GetRiskHistory)
	mux.HandleFunc("/api/history/tech", api.GetTechTrend)
	mux.HandleFunc("/api/history/ownership", api.GetOwnershipHistory)
	mux.HandleFunc("/api/history/asset", api.GetAssetHistory)
	mux.HandleFunc("/api/history/finding", api.GetFindingHistory)
	mux.HandleFunc("/api/graph/nodes", api.GetGraphNodes)
	mux.HandleFunc("/api/graph/edges", api.GetGraphEdges)
	mux.HandleFunc("/api/findings/triage", api.UpdateFindingTriage)
	mux.HandleFunc("/api/findings", api.GetFindings)
	mux.HandleFunc("/api/status", api.GetStatus)

	mux.HandleFunc("/api/v2/events/stream", api.StreamEventsv2)
	mux.HandleFunc("/api/v2/findings/", api.HandleFindingsv2)
	mux.HandleFunc("/api/v2/scan/status", api.GetScanStatusv2)
	mux.HandleFunc("/api/v2/scan/start", api.StartScanv2)
	mux.HandleFunc("/api/v2/programs", api.GetProgramsv2)
	mux.HandleFunc("/api/v2/notifications/pending", api.GetPendingNotificationsv2)
	mux.HandleFunc("/api/v2/notifications/ack/", api.AckNotificationv2)
	mux.HandleFunc("/api/v2/auth/device", api.RegisterDeviceTokenv2)
	mux.HandleFunc("/api/v2/auth/device/", api.RevokeDeviceTokenv2)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		if _, err := w.Write([]byte(DashboardHTML)); err != nil {
			slog.Warn("failed to write dashboard html", "error", err)
		}
	})
}
