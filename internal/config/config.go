package config

import (
	"crypto/subtle"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	OPPort          int      `yaml:"op_port"`
	RPPort          int      `yaml:"rp_port"`
	Issuer          string   `yaml:"issuer"`
	ScopesSupported []string `yaml:"scopes_supported"`
}

type ClientConfig struct {
	ClientID                string   `yaml:"client_id"`
	ClientName              string   `yaml:"client_name"`
	ClientSecret            string   `yaml:"client_secret"`
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

// FindClient looks up a client by ID. Returns nil if not found.
func (c *Config) FindClient(clientID string) *ClientConfig {
	for i := range c.Clients {
		if c.Clients[i].ClientID == clientID {
			return &c.Clients[i]
		}
	}
	return nil
}

// VerifyClientSecret checks the client's secret using constant-time comparison.
// Returns true if the client uses "none" auth or if the secret matches.
func (cl *ClientConfig) VerifyClientSecret(secret string) bool {
	if cl.TokenEndpointAuthMethod == "none" || cl.ClientSecret == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(cl.ClientSecret), []byte(secret)) == 1
}

// Load reads the config file and expands environment variables in string values.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

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
	if len(cfg.Server.ScopesSupported) == 0 {
		cfg.Server.ScopesSupported = []string{"openid", "profile", "email"}
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

	// Default auth method for clients that don't specify one
	for i := range cfg.Clients {
		if cfg.Clients[i].TokenEndpointAuthMethod == "" {
			if cfg.Clients[i].ClientSecret != "" {
				cfg.Clients[i].TokenEndpointAuthMethod = "client_secret_basic"
			} else {
				cfg.Clients[i].TokenEndpointAuthMethod = "none"
			}
		}
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
