package cli

import (
	"fmt"
	"os"

	"github.com/adblocker/adblocker/internal/lists"
	"gopkg.in/yaml.v3"
)

// Config is the YAML config schema. Unknown keys are tolerated.
type Config struct {
	Interfaces             []string       `yaml:"interfaces"`
	AllowlistFile          string         `yaml:"allowlist_file"`
	UpdateIntervalHours    int            `yaml:"update_interval_hours"`
	CleanupIntervalSeconds int            `yaml:"cleanup_interval_seconds"`
	Sources                []lists.Source `yaml:"sources"`
	StaticBlock            []string       `yaml:"static_block"`
}

// LoadConfig parses the YAML file at path with sensible defaults
// applied for any missing fields.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if c.UpdateIntervalHours <= 0 {
		c.UpdateIntervalHours = 24
	}
	if c.CleanupIntervalSeconds <= 0 {
		c.CleanupIntervalSeconds = 60
	}
	if c.AllowlistFile == "" {
		c.AllowlistFile = "/etc/adblocker/allowlist.txt"
	}
	return &c, nil
}
