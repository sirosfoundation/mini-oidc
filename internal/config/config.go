package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	OPPort int    `yaml:"op_port"`
	RPPort int    `yaml:"rp_port"`
	Issuer string `yaml:"issuer"`
}

type ClientConfig struct {
	ClientID                string   `yaml:"client_id"`
	ClientName              string   `yaml:"client_name"`
	RedirectURIs            []string `yaml:"redirect_uris"`
	TokenEndpointAuthMethod string   `yaml:"token_endpoint_auth_method"`
}

type RPConfig struct {
	BaseURL  string `yaml:"base_url"`
	ClientID string `yaml:"client_id"`
	OPIssuer string `yaml:"op_issuer"`
}

type Config struct {
	Server  ServerConfig   `yaml:"server"`
	Clients []ClientConfig `yaml:"clients"`
	RP      RPConfig       `yaml:"rp"`
}

// Load reads the config file and expands environment variables in string values.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	// Expand environment variables in the raw YAML
	expanded := expandEnvVars(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Apply defaults
	if cfg.Server.OPPort == 0 {
		cfg.Server.OPPort = 9005
	}
	if cfg.Server.RPPort == 0 {
		cfg.Server.RPPort = 9006
	}
	if cfg.Server.Issuer == "" {
		cfg.Server.Issuer = fmt.Sprintf("http://localhost:%d", cfg.Server.OPPort)
	}
	if cfg.RP.BaseURL == "" {
		cfg.RP.BaseURL = fmt.Sprintf("http://localhost:%d", cfg.Server.RPPort)
	}
	if cfg.RP.OPIssuer == "" {
		cfg.RP.OPIssuer = cfg.Server.Issuer
	}
	if cfg.RP.ClientID == "" {
		cfg.RP.ClientID = "mini-oidc-rp"
	}

	return &cfg, nil
}

// expandEnvVars expands ${VAR} and ${VAR:-default} patterns in a string.
var envVarRe = regexp.MustCompile(`\$\{([^}]+)\}`)

func expandEnvVars(s string) string {
	return envVarRe.ReplaceAllStringFunc(s, func(match string) string {
		inner := match[2 : len(match)-1] // strip ${ and }
		name, defaultVal, hasDefault := strings.Cut(inner, ":-")
		if val := os.Getenv(name); val != "" {
			return val
		}
		if hasDefault {
			return defaultVal
		}
		return match // leave unexpanded if no env var and no default
	})
}
