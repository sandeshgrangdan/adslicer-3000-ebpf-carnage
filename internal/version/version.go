// Package version exposes build-time identity. The three vars below
// are overridden by `go build -ldflags="-X .../version.Version=..."`.
// Defaults are sensible for a `go run`/dev build.
package version

import "runtime/debug"

// Set by ldflags at build time.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns a single-line human-readable banner suitable for
// `--version` output.
func String() string {
	v, c, d := Version, Commit, Date
	if v == "dev" {
		// Best-effort fallback: read VCS info that the toolchain
		// embedded if the binary was built from a clean tree.
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, s := range info.Settings {
				switch s.Key {
				case "vcs.revision":
					if c == "none" && s.Value != "" {
						c = s.Value
						if len(c) > 7 {
							c = c[:7]
						}
					}
				case "vcs.time":
					if d == "unknown" && s.Value != "" {
						d = s.Value
					}
				}
			}
		}
	}
	return v + " (" + c + " " + d + ")"
}
