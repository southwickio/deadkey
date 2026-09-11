//Package dashboard is deadkey's local web dashboard: `deadkey serve`. A
//server-rendered, single-binary web UI (html/template + embedded assets,
//no separate frontend build) reading from the same SQLite database
//internal/storage/scan.go writes to. See assets.go for why everything is
//embedded rather than loaded at runtime or from a CDN
package dashboard

import (

	"fmt"  //building the host-binding warning message
	"net/http"  //the actual HTTP server

	"github.com/southwickio/deadkey/internal/config"
	"github.com/southwickio/deadkey/internal/storage"

)

//NewHandler builds the complete dashboard http.Handler: every route, the
//embedded static asset server, and CSRF/DNS-rebinding protection wrapping
//the whole thing
//
//http.CrossOriginProtection (added to the Go standard library in Go 1.25)
//rejects non-safe cross-origin browser requests using the Sec-Fetch-Site
//and Origin headers - specifically the protection a local server like this
//needs against a malicious webpage open in another tab silently sending
//requests to it. This matters more here than for a typical local dev
//server: this dashboard has write routes (vote, ignore, unignore) that
//change what a SECURITY tool reports, and a real, documented category of
//attack (DNS rebinding against local servers) exists specifically for this
//situation. GET/HEAD/OPTIONS requests are always allowed regardless -
//correct, since every read route here is one of those methods and none of
//them cause any state change (a hard rule this dashboard follows
//throughout: nothing changes state on a GET)
func NewHandler(db *storage.DB, cfg *config.Config, host string) (http.Handler, error) {

	h := &handlers{db: db, cfg: cfg, hostWarning: HostWarning(host)}

	static, err := newStaticHandler()
	if err != nil {

		return nil, err

	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", h.handleHome)
	mux.HandleFunc("GET /scans/{id}", h.handleScan)
	mux.HandleFunc("GET /scans/{id}/rows", h.handleRows)
	mux.HandleFunc("POST /credentials/{id}/feedback", h.handleFeedback)
	mux.HandleFunc("POST /credentials/{id}/ignore", h.handleIgnore)
	mux.HandleFunc("POST /credentials/{id}/unignore", h.handleUnignore)
	mux.Handle("GET /static/", static)

	return http.NewCrossOriginProtection().Handler(mux), nil

}

//HostWarning returns a non-empty message when host is anything other than a
//loopback address - shown at the top of every page (see ViewData.HostWarning
//and layout.html.tmpl). Binding this dashboard to a non-localhost address
//means its write routes (ignore, vote) become reachable, and its read
//routes readable, by anything else that can reach that address - worth
//surfacing loudly rather than a silent difference from the (safe) default
func HostWarning(host string) string {

	if host == "127.0.0.1" || host == "localhost" || host == "::1" {

		return ""

	}

	return fmt.Sprintf(
		"Bound to %s, not localhost. Scan results (credential locations, risk findings - never the secrets themselves) and the ability to vote on or ignore findings will be reachable by anything that can reach this address.",
		host,
	)

}
