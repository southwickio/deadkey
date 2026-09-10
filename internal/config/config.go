//Package config manages deadkey's local settings file (config.json): telemetry
//opt-in state and persisted CLI defaults. Separate from internal/storage's
//SQLite database. This file has to exist and be readable before any scan has
//ever run, so it can't live inside the scan-results database
package config

import (

	"crypto/rand"  //generating the anonymous install ID
	"encoding/hex"  //formatting the install ID as a string
	"encoding/json"  //reading and writing config.json
	"fmt"  //building error messages
	"os"  //filesystem access
	"path/filepath"  //building paths correctly across operating systems
	"runtime"  //detecting the OS, for the Windows-specific directory choice
	"time"  //stamping when telemetry was asked about

)

//CurrentVersion is bumped whenever Config's shape changes in a way that needs
//explicit handling on load. See Load's doc comment
const CurrentVersion = 1

//Telemetry holds the anonymous, opt-in risk-feedback telemetry settings.
//Opt-in, not opt-out. AskedAt is what gates whether the person has ever been
//prompted at all, separate from whether they said yes
type Telemetry struct {

	OptedIn   bool      `json:"opted_in"`
	AskedAt   time.Time `json:"asked_at"`

	//InstallID is a random, locally-generated identifier, never tied to any
	//account or email. Generated once the first time telemetry is ever
	//addressed (whether the answer was yes or no, so a later opt-in reuses the
	//same ID rather than fragmenting history)
	InstallID string `json:"install_id"`

}

//Defaults holds optional persisted CLI defaults (for example: someone who
//always runs `deadkey scan --provider aws --provider twilio` can set that once
//via `deadkey config` instead of retyping it every time). Nil/empty means "no
//override, use the built-in default"
type Defaults struct {

	Providers []string `json:"providers,omitempty"`
	Paths     []string `json:"paths,omitempty"`

}

//Config is the full contents of config.json
type Config struct {

	ConfigVersion int       `json:"config_version"`
	Telemetry     Telemetry `json:"telemetry"`
	Defaults      Defaults  `json:"defaults"`

	path string  //where this was loaded from/will be saved to. Not serialized

}

//Dir returns the directory deadkey stores its local files in: this config.json,
//and (the SQLite database. 'override' is the --config flag's value, if one was
//set. Empty means use the default
//
//On Windows, this resolves via os.UserConfigDir() (%AppData%), specifically
//to avoid a real, confirmed issue: SQLite's WAL mode (used by internal/storage)
//is documented as unreliable over network and cloud-sync-backed filesystems,
//and Windows' "Known Folder Move" feature can silently redirect a user's home
//directory into a OneDrive-synced path without them having chosen that for this
//specific purpose. %AppData% is not swept into OneDrive's default sync scope,
//so it's the safer default regardless of any individual machine's
//configuration. This isn't a workaround for one setup, it's the correct default
//for every Windows install
//
//On Linux/macOS, this stays the ~/.deadkey convention already referenced
//throughout this project's roadmap docs. Neither platform has an equivalent
//silent-redirection risk by default
func Dir(override string) (string, error) {

	if override != "" {

		return override, nil

	}

	if runtime.GOOS == "windows" {

		base, err := os.UserConfigDir()
		if err != nil {

			return "", fmt.Errorf("config: resolving Windows config directory: %w", err)

		}
		return filepath.Join(base, "deadkey"), nil

	}

	home, err := os.UserHomeDir()
	if err != nil {

		return "", fmt.Errorf("config: resolving home directory: %w", err)

	}
	return filepath.Join(home, ".deadkey"), nil

}

//EnsureDir creates dir (and any missing parents) if it doesn't already exist.
//Idempotent, safe to call at the start of every command. This is the shared
//precondition every subcommand relies on rather than each remembering to create
//it individually
func EnsureDir(dir string) error {

	if err := os.MkdirAll(dir, 0o700); err != nil {

		return fmt.Errorf("config: creating %s: %w", dir, err)

	}
	return nil

}

func configPath(dir string) string {

	return filepath.Join(dir, "config.json")

}

//Load reads config.json from dir. A missing file is not an error; it returns a
//fresh, zero-value Config (IsFirstRun reports true for it), since most machines
//running deadkey for the first time simply won't have one yet
func Load(dir string) (*Config, error) {

	p := configPath(dir)

	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {

		return &Config{ConfigVersion: CurrentVersion, path: p}, nil

	}
	if err != nil {

		return nil, fmt.Errorf("config: reading %s: %w", p, err)

	}

	var c Config
	if err := json.Unmarshal(data, &c); err != nil {

		return nil, fmt.Errorf("config: parsing %s: %w", p, err)

	}
	c.path = p

	return &c, nil

}

//Save writes c back to its original path, atomically: write to a temp file in
//the same directory, then rename over the real path. This means a crash or
//power loss mid-write can never leave a truncated, unparseable config.json
//behind. The rename either fully happens or fully doesn't
func (c *Config) Save() error {

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {

		return fmt.Errorf("config: encoding: %w", err)

	}

	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {

		return fmt.Errorf("config: writing temp file: %w", err)

	}
	if err := os.Rename(tmp, c.path); err != nil {

		return fmt.Errorf("config: finalizing %s: %w", c.path, err)

	}

	return nil

}

//IsFirstRun reports whether telemetry has ever been asked about. Deliberately
//keyed on AskedAt, not on whether config.json existed at all. The file could
//exist for other reasons (persisted Defaults set via `deadkey config`)
//before telemetry is ever addressed
func (c *Config) IsFirstRun() bool {

	return c.Telemetry.AskedAt.IsZero()

}

//SetTelemetry records the person's answer (or the safe non-interactive default.
//See cmd/deadkey/scan.go), generating a fresh anonymous InstallID
//the first time this is ever called
func (c *Config) SetTelemetry(optedIn bool) {

	c.Telemetry.OptedIn = optedIn
	c.Telemetry.AskedAt = time.Now().UTC()
	if c.Telemetry.InstallID == "" {

		c.Telemetry.InstallID = newInstallID()

	}

}

func newInstallID() string {

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {

		//crypto/rand failing is effectively unheard-of on any real machine.
		//Falling back to a static marker is safer than a panic taking down a
		//security tool over telemetry bookkeeping
		return "unavailable"

	}
	return hex.EncodeToString(b)

}