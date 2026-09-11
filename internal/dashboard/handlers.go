package dashboard

import (

	"fmt"  //building error messages
	"net/http"  //serving requests
	"strconv"  //parsing scan/credential IDs from the URL
	"time"  //computing AgeBucket

	"github.com/southwickio/deadkey/internal/config"
	"github.com/southwickio/deadkey/internal/models"
	"github.com/southwickio/deadkey/internal/output"
	"github.com/southwickio/deadkey/internal/storage"
	"github.com/southwickio/deadkey/internal/telemetry"

)

//handlers holds what every route needs. Deliberately a small, explicit struct
//rather than package-level globals. net/http handlers are registered once at
//startup (see server.go) and this makes what state they close over visible in
//one place
type handlers struct {

	db          *storage.DB
	cfg         *config.Config
	hostWarning string

}

//handleHome sends '/' to the most recently started scan, or renders the empty
//state directly if none has ever run; the same content handleScan would show
//for a scan that doesn't exist, without a redirect loop
func (h *handlers) handleHome(w http.ResponseWriter, r *http.Request) {

	id, ok, err := storage.LatestScanID(h.db)
	if err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return

	}
	if !ok {

		h.renderPage(w, ViewData{Empty: true, HostWarning: h.hostWarning})
		return

	}

	http.Redirect(w, r, fmt.Sprintf("/scans/%d", id), http.StatusSeeOther)

}

//handleScan renders the full dashboard page for one scan. {id} may be a literal
//scan ID, or "latest"
func (h *handlers) handleScan(w http.ResponseWriter, r *http.Request) {

	view, ok, err := h.loadView(r)
	if err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return

	}
	if !ok {

		http.NotFound(w, r)
		return

	}

	h.renderPage(w, view)

}

//handleRows renders just the row table body, for the show/hide-ignored toggle's
//htmx swap. No full page reload for a filter change
func (h *handlers) handleRows(w http.ResponseWriter, r *http.Request) {

	view, ok, err := h.loadView(r)
	if err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return

	}
	if !ok {

		http.NotFound(w, r)
		return

	}

	if err := parsedTemplates.ExecuteTemplate(w, "rows", view.RowViews); err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)

	}

}

//handleFeedback records an up/down vote and sends it via internal/telemetry,
//A telemetry send failure is deliberately not surfaced to the person clicking
//the button. See telemetry.SendFeedback's doc comment for why that's the
//caller's decision to make, not the sender's
func (h *handlers) handleFeedback(w http.ResponseWriter, r *http.Request) {

	credentialID, scanID, ok := parseCredentialAndScan(r)
	if !ok {

		http.Error(w, "invalid credential or scan id", http.StatusBadRequest)
		return

	}

	vote := r.URL.Query().Get("vote")
	if vote != "up" && vote != "down" {

		http.Error(w, "vote must be \"up\" or \"down\"", http.StatusBadRequest)
		return

	}

	row, ok, err := storage.GetAssessment(h.db, scanID, credentialID)
	if err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return

	}
	if !ok {

		http.NotFound(w, r)
		return

	}

	if h.cfg.IsFirstRun() {

		//A dashboard button click has no interactive terminal to prompt on the
		//way cmd/deadkey/scan.go's first-run prompt does. A feedback action is
		//the first-run moment here. Opting in is implied by clicking
		//Agree/Disagree at all, since there is no other way to ask on this
		//surface
		h.cfg.SetTelemetry(true)
		_ = h.cfg.Save()

	}

	if h.cfg.Telemetry.OptedIn {

		payload := models.FeedbackPayload{

			InstallID:      h.cfg.Telemetry.InstallID,
			Provider:       row.Provider,
			CredentialType: models.CredentialSubtype(row.Subtype),
			ModifierCodes:  modifierCodes(row.RiskModifiers),

			//DiscoveryConfidence here is an approximation, not the original
			//captured value: DiscoveryEvidence's own float Confidence (see
			//models/evidence.go) was never persisted to storage; only
			//Credential.DiscoveryConfidence's coarser string enum was (see
			//assessments.go). Mapped to the same two-point scale already used
			//as a stand-in elsewhere in this project (internal/risk's own
			//stated simplification): exact/manual discovery -> 1.0,
			//pattern-matched -> 0.6. A real fix would mean persisting
			//DiscoveryEvidence.Confidence itself in a future schema version
			DiscoveryMethod:     row.DiscoveryConfidence,
			DiscoveryConfidence: approximateConfidence(row.DiscoveryConfidence),

			ValidationStatus: models.ValidationStatus(row.ValidationStatus),
			ActivityQuality:  models.ActivityQuality(row.ActivityQuality),

			RiskTier: models.RiskTier(row.RiskTier),
			Vote:     vote,
		}
		if row.RiskScore != nil {

			payload.RiskScore = *row.RiskScore

		}
		payload.AgeBucket = ageBucket(row.FirstSeenAt)

		//Errors are intentionally not surfaced to the person clicking the
		//button. See this handler's doc comment
		_ = telemetry.SendFeedback(r.Context(), payload)

	}

	h.renderRow(w, r, scanID, credentialID)

}

//handleIgnore adds credentialID to the ignore list and re-renders its row
func (h *handlers) handleIgnore(w http.ResponseWriter, r *http.Request) {

	h.applyIgnoreChange(w, r, true)

}

//handleUnignore removes credentialID from the ignore list and re-renders
//its row
func (h *handlers) handleUnignore(w http.ResponseWriter, r *http.Request) {

	h.applyIgnoreChange(w, r, false)

}

func (h *handlers) applyIgnoreChange(w http.ResponseWriter, r *http.Request, ignore bool) {

	credentialID, scanID, ok := parseCredentialAndScan(r)
	if !ok {

		http.Error(w, "invalid credential or scan id", http.StatusBadRequest)
		return

	}

	provider, location, err := storage.GetCredential(h.db, credentialID)
	if err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return

	}

	if ignore {

		err = storage.AddIgnore(h.db, provider, location, "ignored from dashboard")

	} else {

		_, err = storage.RemoveIgnore(h.db, location)

	}
	if err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return

	}

	h.renderRow(w, r, scanID, credentialID)

}

//renderRow re-fetches and re-renders a single row, used after any action that
//changes that row's own state (vote, ignore, unignore). Refetching rather than
//mutating an in-memory copy keeps this handler simple and guarantees the
//rendered row always reflects exactly what storage now says, not what the
//handler assumed it changed
func (h *handlers) renderRow(w http.ResponseWriter, r *http.Request, scanID, credentialID int64) {

	row, ok, err := storage.GetAssessment(h.db, scanID, credentialID)
	if err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return

	}
	if !ok {

		http.NotFound(w, r)
		return

	}

	if err := parsedTemplates.ExecuteTemplate(w, "row", RowView{AssessmentRow: row, ScanID: scanID}); err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)

	}

}

//loadView is the shared data-fetching step behind both the full page
//(handleScan) and the row-fragment (handleRows) routes, so the two can never
//drift out of sync on what "the current view" actually means
func (h *handlers) loadView(r *http.Request) (ViewData, bool, error) {

	scanID, ok := resolveScanID(h.db, r)
	if !ok {

		return ViewData{}, false, nil

	}

	scan, ok, err := storage.GetScan(h.db, scanID)
	if err != nil || !ok {

		return ViewData{}, false, err

	}

	rows, err := storage.ListForScan(h.db, scanID)
	if err != nil {

		return ViewData{}, false, err

	}

	showIgnored := r.URL.Query().Get("show_ignored") == "1"
	minRisk := r.URL.Query().Get("min_risk")
	rows = output.FilterByMinRisk(rows, minRisk, showIgnored)

	views := make([]RowView, 0, len(rows))
	for _, row := range rows {

		views = append(views, RowView{AssessmentRow: row, ScanID: scanID})

	}

	recent, err := storage.ListRecentScans(h.db, 10)
	if err != nil {

		return ViewData{}, false, err

	}

	return ViewData{

		Scan:        scan,
		RecentScans: recent,
		RowViews:    views,
		ShowIgnored: showIgnored,
		MinRisk:     minRisk,
		HostWarning: h.hostWarning,

	}, true, nil

}

func (h *handlers) renderPage(w http.ResponseWriter, view ViewData) {

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := parsedTemplates.ExecuteTemplate(w, "layout", view); err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)

	}

}

//resolveScanID reads the {id} path value, which may be the literal string
//"latest" or a numeric scan ID
func resolveScanID(db *storage.DB, r *http.Request) (int64, bool) {

	idStr := r.PathValue("id")
	if idStr == "latest" {

		id, ok, err := storage.LatestScanID(db)
		return id, ok && err == nil

	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	return id, err == nil

}

//parseCredentialAndScan reads {id} (the credential ID) from the path and
//scan_id from the query string. Every write route (feedback/ignore/unignore)
//needs both: which credential to act on, and which scan's row to re-render
//afterward
func parseCredentialAndScan(r *http.Request) (credentialID, scanID int64, ok bool) {

	credentialID, err1 := strconv.ParseInt(r.PathValue("id"), 10, 64)
	scanID, err2 := strconv.ParseInt(r.URL.Query().Get("scan_id"), 10, 64)
	return credentialID, scanID, err1 == nil && err2 == nil

}

func modifierCodes(modifiers []models.RiskModifier) []string {

	codes := make([]string, 0, len(modifiers))
	for _, m := range modifiers {

		codes = append(codes, m.Code)

	}
	return codes

}

//approximateConfidence maps Credential.DiscoveryConfidence's string enum to a
//float, since the original DiscoveryEvidence.Confidence value it stands in for
//was never persisted. See handleFeedback's doc comment
func approximateConfidence(discoveryConfidence string) float64 {

	if discoveryConfidence == "pattern_matched" {

		return 0.6

	}
	return 1.0

}

//ageBucket turns firstSeenAt into a coarse, human-readable range, matching
//models.FeedbackPayload.AgeBucket's documented intent: precise enough to be
//useful in aggregate, vague enough that it can't fingerprint one specific
//credential's exact creation time
func ageBucket(firstSeenAt time.Time) string {

	if firstSeenAt.IsZero() {

		return "unknown"

	}

	days := time.Since(firstSeenAt).Hours() / 24
	switch {

	case days < 30:
		return "0-30 days"
	case days < 90:
		return "30-90 days"
	case days < 180:
		return "90-180 days"
	default:
		return "180+ days"

	}

}