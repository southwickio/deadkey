package dashboard

import (

	"embed"  //compiles templates/static assets directly into the binary

)

//templatesFS and staticFS are embedded at compile time, so `deadkey serve`
//remains a single binary with no runtime file dependencies - the dashboard
//works identically whether it's the binary that was just built here or one
//someone downloaded via curl | sh and ran on an entirely different machine.
//This is the same reasoning already applied to modernc.org/sqlite
//(internal/storage/db.go): no runtime dependency, no separate install step,
//no risk of a missing file breaking the dashboard on a machine other than
//the one it was built on
//
//static/htmx.min.js is a real, unmodified vendored copy of htmx.org (fetched
//via `npm pack htmx.org`), not loaded from a CDN. Deliberate: this dashboard
//displays security-sensitive-adjacent data (credential locations, risk
//findings) on a local machine, and pulling any script from an external CDN
//on every page load would be a real, if small, supply-chain/privacy smell
//specifically for a security tool - and would break the dashboard entirely
//on an offline or air-gapped machine, which is a real, plausible way this
//tool gets used
//
//go:embed templates/*.tmpl
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS
