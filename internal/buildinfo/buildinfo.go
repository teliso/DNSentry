// Package buildinfo reports the version of the running binary.
package buildinfo

import "runtime/debug"

// Version is set at link time: -ldflags "-X github.com/teliso/DNSentry/internal/buildinfo.Version=v1.2.3".
var Version = ""

// String returns Version, or the VCS revision recorded by the Go toolchain,
// or "dev".
func String() string {
	if Version != "" {
		return Version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	revision, modified := "", false
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	if revision == "" {
		return "dev"
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified {
		revision += "-dirty"
	}
	return "dev-" + revision
}
