package dashboard

import (

	"fmt"  //building an error message
	"html/template"  //parsing and rendering the embedded templates. html/template,
		//not text/template - it auto-escapes values (credential locations,
		//error messages) that came from providers/discovery, not something
		//deadkey's own code wrote, so this matters for real, not just in
		//theory
	"io/fs"  //building a sub-filesystem for the static asset handler
	"net/http"  //the static asset handler's type

	"github.com/southwickio/deadkey/internal/storage"

)

//RowView pairs an AssessmentRow with the scan ID it belongs to. Templates
//need the scan ID to build the vote/ignore/unignore hx-post URLs for each
//row, and AssessmentRow itself deliberately doesn't carry it (it's a
//per-scan query result, not aware of which scan asked for it - see
//storage.ListForScan)
type RowView struct {

	storage.AssessmentRow
	ScanID int64

}

//ViewData is what every dashboard page/fragment renders from
type ViewData struct {

	//Empty is true when no scan has ever run. The template shows a single
	//friendly message and nothing else in that case
	Empty bool

	Scan        storage.Scan
	RecentScans []storage.Scan
	RowViews    []RowView

	ShowIgnored bool
	MinRisk     string

	//HostWarning is set (and rendered) only when serve was started with
	//--host pointed at something other than localhost. See server.go
	HostWarning string

}

//parsedTemplates is parsed once, at package init, from the embedded
//filesystem - not re-parsed per request. The templates are compiled into
//the binary; there is nothing to hot-reload, and re-parsing per request
//would be pure overhead with no corresponding benefit
var parsedTemplates = template.Must(template.ParseFS(templatesFS, "templates/*.tmpl"))

//newStaticHandler serves the embedded CSS and vendored htmx under /static/.
//fs.Sub trims the "static" prefix so a request for /static/style.css
//correctly resolves to the embedded static/style.css file, not
//static/static/style.css
func newStaticHandler() (http.Handler, error) {

	sub, err := fs.Sub(staticFS, "static")
	if err != nil {

		return nil, fmt.Errorf("dashboard: building static asset filesystem: %w", err)

	}

	return http.StripPrefix("/static/", http.FileServerFS(sub)), nil

}
