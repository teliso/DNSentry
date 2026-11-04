package app

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/teliso/DNSentry/internal/auth"
	"github.com/teliso/DNSentry/internal/fsutil"
)

// importConfigPassword lets the operator set the console login by editing the
// configuration file:
//
//	web:
//	  auth:
//	    username: admin
//	    password: abc        # plain text (any length) or a bcrypt hash
//
// At start the credentials are moved into the login file (stored as a bcrypt
// hash) and the password is removed from the configuration file, so the plain
// text does not stay on disk — and never reaches the configuration history.
func importConfigPassword(store *auth.Store) error {
	path := configPath()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil || root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil // loadConfig reports malformed YAML
	}
	web := mappingValue(root.Content[0], "web")
	block := mappingValue(web, "auth")
	if block == nil {
		return nil
	}
	username, password := scalarValue(mappingValue(block, "username")), scalarValue(mappingValue(block, "password"))
	if password != "" {
		if username == "" {
			username = store.Username()
		}
		if username == "" {
			username = "admin"
		}
		if err := store.Import(username, password); err != nil {
			return fmt.Errorf("web.auth in %s: %w", path, err)
		}
		slog.Info("console login set from the configuration file", "username", username)
	}
	removeKey(web, "auth")
	out, err := yaml.Marshal(&root)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, out, 0600)
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func scalarValue(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return node.Value
}

func removeKey(node *yaml.Node, key string) {
	if node == nil || node.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			node.Content = append(node.Content[:i], node.Content[i+2:]...)
			return
		}
	}
}
