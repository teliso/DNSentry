package app

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/teliso/DNSentry/internal/fsutil"
)

// Every saved configuration is kept as a version in <config dir>/history so
// that a bad change can be traced and undone. Versions are full copies of the
// YAML file (mode 0600, like the configuration itself).
const (
	maxConfigVersions     = 30
	configVersionIDFormat = "20060102T150405.000Z"
	maxListedChanges      = 12
)

var configVersionID = regexp.MustCompile(`^\d{8}T\d{6}\.\d{3}Z$`)

// ConfigVersion describes one saved configuration.
type ConfigVersion struct {
	ID   string `json:"id"`
	Time string `json:"time"`
	// Current marks the version that equals the configuration in use.
	Current bool `json:"current"`
	// Changes lists the settings that differ from the previous version, as
	// dotted keys (for example "dns.upstreams"); values are never included
	// because they can be secrets.
	Changes []string `json:"changes"`
	// MoreChanges counts changed settings beyond maxListedChanges.
	MoreChanges int `json:"more_changes,omitempty"`
}

func configHistoryDir() string { return filepath.Join(filepath.Dir(configPath()), "history") }

func configVersionPath(id string) string { return filepath.Join(configHistoryDir(), id+".yaml") }

// configVersionIDs returns the stored version IDs, newest first.
func configVersionIDs() []string {
	entries, err := os.ReadDir(configHistoryDir())
	if err != nil {
		return nil
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if id := name[:max(len(name)-len(".yaml"), 0)]; !entry.IsDir() && filepath.Ext(name) == ".yaml" && configVersionID.MatchString(id) {
			ids = append(ids, id)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	return ids
}

// archiveConfigVersion stores data as a new version unless it equals the newest
// one, and prunes old versions.
func archiveConfigVersion(data []byte, at time.Time) error {
	ids := configVersionIDs()
	if len(ids) > 0 {
		if newest, err := os.ReadFile(configVersionPath(ids[0])); err == nil && bytes.Equal(newest, data) {
			return nil
		}
	}
	at = at.UTC()
	id := at.Format(configVersionIDFormat)
	for len(ids) > 0 && id <= ids[0] { // keep IDs strictly increasing
		at = at.Add(time.Millisecond)
		id = at.Format(configVersionIDFormat)
	}
	if err := fsutil.WriteFileAtomic(configVersionPath(id), data, 0600); err != nil {
		return err
	}
	ids = append([]string{id}, ids...)
	for _, old := range ids[min(maxConfigVersions, len(ids)):] {
		_ = os.Remove(configVersionPath(old))
	}
	return nil
}

func flattenConfig(prefix string, value any, out map[string]any) {
	if nested, ok := value.(map[string]any); ok {
		for key, child := range nested {
			name := key
			if prefix != "" {
				name = prefix + "." + key
			}
			flattenConfig(name, child, out)
		}
		return
	}
	out[prefix] = value
}

func flattenYAML(data []byte) map[string]any {
	var parsed map[string]any
	if yaml.Unmarshal(data, &parsed) != nil {
		return nil
	}
	flat := make(map[string]any)
	flattenConfig("", parsed, flat)
	delete(flat, "version")
	return flat
}

// configChanges returns the dotted keys whose values differ, sorted.
func configChanges(newer, older []byte) []string {
	after, before := flattenYAML(newer), flattenYAML(older)
	changed := map[string]struct{}{}
	for key, value := range after {
		if previous, ok := before[key]; !ok || !reflect.DeepEqual(value, previous) {
			changed[key] = struct{}{}
		}
	}
	for key := range before {
		if _, ok := after[key]; !ok {
			changed[key] = struct{}{}
		}
	}
	keys := make([]string, 0, len(changed))
	for key := range changed {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// listConfigVersions returns the stored versions, newest first.
func listConfigVersions() []ConfigVersion {
	ids := configVersionIDs()
	current, _ := os.ReadFile(configPath())
	versions := make([]ConfigVersion, 0, len(ids))
	var newer []byte
	for index, id := range ids {
		data, err := os.ReadFile(configVersionPath(id))
		if err != nil {
			continue
		}
		at, _ := time.Parse(configVersionIDFormat, id)
		version := ConfigVersion{ID: id, Time: at.Format(time.RFC3339), Current: index == 0 && bytes.Equal(data, current), Changes: []string{}}
		if index > 0 && newer != nil {
			// versions[index-1] holds the newer content; describe what it changed
			previous := &versions[len(versions)-1]
			keys := configChanges(newer, data)
			previous.MoreChanges = max(len(keys)-maxListedChanges, 0)
			previous.Changes = keys[:min(len(keys), maxListedChanges)]
		}
		newer = data
		versions = append(versions, version)
	}
	return versions
}

// loadConfigVersion reads and validates a stored version.
func loadConfigVersion(id string) (*Config, error) {
	if !configVersionID.MatchString(id) {
		return nil, fmt.Errorf("invalid version id")
	}
	data, err := os.ReadFile(configVersionPath(id))
	if err != nil {
		return nil, fmt.Errorf("version not found")
	}
	fileConfig := new(yamlConfig)
	if err := yaml.Unmarshal(data, fileConfig); err != nil {
		return nil, fmt.Errorf("invalid YAML in version: %w", err)
	}
	validated, err := validateConfig(fileConfig.toConfig())
	if err != nil {
		return nil, fmt.Errorf("invalid configuration in version: %w", err)
	}
	return validated, nil
}

// previousConfigVersionID is the newest version that differs from the
// configuration in use — what "restore the last configuration" means.
func previousConfigVersionID() (string, bool) {
	versions := listConfigVersions()
	for _, version := range versions {
		if !version.Current {
			return version.ID, true
		}
	}
	return "", false
}
