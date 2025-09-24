// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/jcchavezs/mergefs"
	"github.com/jcchavezs/mergefs/io"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(corazaModule{})
	httpcaddyfile.RegisterHandlerDirective("coraza_waf", parseCaddyfile)
}

// ResponseOverride defines custom WAF response behavior that overrides file-based SecDefaultAction
type ResponseOverride struct {
	OverrideFileDefaults bool              `json:"override_file_defaults"`    // Skip file-based SecDefaultAction directives
	DefaultActions       map[int]string    `json:"default_actions,omitempty"` // Phase -> action mapping (e.g., {1: "deny,status:404", 2: "deny,status:404"})
	Headers              map[string]string `json:"headers,omitempty"`         // Additional response headers
}

// corazaModule is a Web Application Firewall implementation for Caddy.
type corazaModule struct {
	// deprecated
	Include          []string          `json:"include"`
	Directives       string            `json:"directives"`
	LoadOWASPCRS     bool              `json:"load_owasp_crs"`
	ResponseOverride *ResponseOverride `json:"response_override,omitempty"` // Override file-based SecDefaultAction

	logger *zap.Logger
	waf    coraza.WAF
}

// CaddyModule returns the Caddy module information.
func (corazaModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.waf",
		New: func() caddy.Module { return new(corazaModule) },
	}
}

// Provision implements caddy.Provisioner.
func (m *corazaModule) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)

	config := coraza.NewWAFConfig().
		WithDebugLogger(newLogger(m.logger)).
		WithErrorCallback(newErrorCb(m.logger))

	if m.LoadOWASPCRS {
		config = config.WithRootFS(mergefs.Merge(coreruleset.FS, io.OSFS))
	}

	// Process directives with optional SecDefaultAction filtering
	if m.Directives != "" {
		processedDirectives := m.processDirectives(m.Directives)
		config = config.WithDirectives(processedDirectives)
	}

	// Add custom SecDefaultAction directives if response override is configured
	if m.ResponseOverride != nil && len(m.ResponseOverride.DefaultActions) > 0 {
		customDirectives := m.generateCustomDefaultActions()
		if customDirectives != "" {
			config = config.WithDirectives(customDirectives)
		}
	}

	if len(m.Include) > 0 {
		m.logger.Warn("'include' field is deprecated, please use the Include directive inside 'directives' field instead")
		for _, file := range m.Include {
			if strings.Contains(file, "*") {
				m.logger.Debug("Preparing to expand glob", zap.String("pattern", file))
				// we get files as expandables globs (with wildcard patterns)
				fs, err := filepath.Glob(file)
				if err != nil {
					return err
				}
				m.logger.Debug("Glob expanded", zap.String("pattern", file), zap.Strings("files", fs))
				for _, f := range fs {
					config = config.WithDirectivesFromFile(f)
				}
			} else {
				m.logger.Debug("File was not a pattern, compiling it", zap.String("file", file))
				config = config.WithDirectivesFromFile(file)
			}
		}
	}

	var err error
	m.waf, err = coraza.NewWAF(config)
	return err
}

// Validate implements caddy.Validator.
func (m *corazaModule) Validate() error {
	return nil
}

var errInterruptionTriggered = errors.New("interruption triggered")

// processDirectives filters out SecDefaultAction directives if override is enabled
func (m *corazaModule) processDirectives(directives string) string {
	if m.ResponseOverride == nil || !m.ResponseOverride.OverrideFileDefaults {
		// No override configured, return directives as-is
		return directives
	}

	// Filter out SecDefaultAction lines
	lines := strings.Split(directives, "\n")
	var filteredLines []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip SecDefaultAction directives (case-insensitive)
		if !strings.HasPrefix(strings.ToLower(trimmed), "secdefaultaction") {
			filteredLines = append(filteredLines, line)
		} else {
			if m.logger != nil {
				m.logger.Debug("Skipping file-based SecDefaultAction due to override", zap.String("line", trimmed))
			}
		}
	}

	return strings.Join(filteredLines, "\n")
}

// generateCustomDefaultActions creates custom SecDefaultAction directives
func (m *corazaModule) generateCustomDefaultActions() string {
	if m.ResponseOverride == nil || len(m.ResponseOverride.DefaultActions) == 0 {
		return ""
	}

	var directives []string

	// Generate SecDefaultAction for each configured phase
	for phase, action := range m.ResponseOverride.DefaultActions {
		if action != "" {
			directives = append(directives, fmt.Sprintf("SecDefaultAction \"phase:%d,%s\"", phase, action))
		}
	}

	return strings.Join(directives, "\n")
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m corazaModule) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	id := randomString(16)
	tx := m.waf.NewTransactionWithID(id)
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	// Early return, Coraza is not going to process any rule
	if tx.IsRuleEngineOff() {
		// response writer is not going to be wrapped, but used as-is
		// to generate the response
		return next.ServeHTTP(w, r)
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	repl.Set("http.transaction_id", id)

	// ProcessRequest is just a wrapper around ProcessConnection, ProcessURI,
	// ProcessRequestHeaders and ProcessRequestBody.
	// It fails if any of these functions returns an error and it stops on interruption.
	if it, err := processRequest(tx, r); err != nil {
		return caddyhttp.HandlerError{
			StatusCode: http.StatusInternalServerError,
			ID:         tx.ID(),
			Err:        err,
		}
	} else if it != nil {
		// Log WAF violation immediately when interruption occurs
		var uniqueID, ruleID, ruleFile string
		matchedRules := tx.MatchedRules()

		clientIP := r.RemoteAddr
		if idx := strings.Index(clientIP, ":"); idx != -1 {
			clientIP = clientIP[:idx]
		}

		// Extract rule information from matched rules

		// Extract rule information from the last non-inline rule
		var blockingRule types.MatchedRule
		for _, rule := range matchedRules {
			// Skip inline rules for rule_file, but keep for fallback
			if rule.Rule().File() != "_inline_" {
				ruleID = fmt.Sprintf("%d", rule.Rule().ID())
				ruleFile = rule.Rule().File()
			}
			blockingRule = rule
		}

		if blockingRule != nil {
			meta := blockingRule.ErrorLog()
			// Look for unique_id in the rule metadata
			if meta != "" {
				if idx := strings.Index(meta, "[unique_id \""); idx != -1 {
					end := strings.Index(meta[idx:], "\"]")
					if end != -1 {
						uniqueID = meta[idx+12 : idx+end]
					}
				}
			}
			// Get rule ID and file from the blocking rule
			ruleID = fmt.Sprintf("%d", blockingRule.Rule().ID())
			ruleFile = blockingRule.Rule().File()

		} else {
			m.logger.Debug("No blocking rule found")
		}

		// Provide defaults if values are empty
		if ruleID == "" || ruleID == "0" {
			ruleID = "unknown"
		}
		if ruleFile == "" {
			ruleFile = "unknown"
		}
		if uniqueID == "" {
			uniqueID = tx.ID() // Use transaction ID as fallback
		}

		m.logger.Error("WAF rule violation detected",
			zap.String("hostname", r.Host),
			zap.String("uri", r.RequestURI),
			zap.String("client_ip", clientIP),
			zap.String("unique_id", uniqueID),
			zap.String("rule_id", ruleID),
			zap.String("rule_file", ruleFile),
		)

		return caddyhttp.HandlerError{
			StatusCode: obtainStatusCodeFromInterruptionOrDefault(it, http.StatusOK),
			ID:         tx.ID(),
			Err:        errInterruptionTriggered,
		}
	}

	ww, processResponse := wrap(w, r, tx)

	// We continue with the other middlewares by catching the response
	if err := next.ServeHTTP(ww, r); err != nil {
		return err
	}

	return processResponse(tx, r)
}

// Unmarshal Caddyfile implements caddyfile.Unmarshaler.
func (m *corazaModule) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.Err("expected token following filter")
	}
	m.Include = []string{}
	for d.NextBlock(0) {
		key := d.Val()
		switch key {
		case "load_owasp_crs":
			if d.NextArg() {
				return d.ArgErr()
			}
			m.LoadOWASPCRS = true
		case "directives", "include":
			var value string
			if !d.Args(&value) {
				// not enough args
				return d.ArgErr()
			}

			if d.NextArg() {
				// too many args
				return d.ArgErr()
			}

			switch key {
			case "include":
				m.Include = append(m.Include, value)
			case "directives":
				m.Directives = value
			}
		case "response_override":
			if m.ResponseOverride == nil {
				m.ResponseOverride = &ResponseOverride{}
			}
			for d.NextBlock(1) {
				if err := m.parseResponseOverride(d); err != nil {
					return err
				}
			}
		default:
			return d.Errf("invalid key %q", key)
		}
	}

	return nil
}

// parseResponseOverride parses response override configuration from Caddyfile
func (m *corazaModule) parseResponseOverride(d *caddyfile.Dispenser) error {
	key := d.Val()

	switch key {
	case "override_file_defaults":
		if d.NextArg() {
			return d.ArgErr()
		}
		m.ResponseOverride.OverrideFileDefaults = true

	case "default_action":
		if !d.NextArg() {
			return d.ArgErr()
		}
		phase, err := strconv.Atoi(d.Val())
		if err != nil {
			return d.Errf("invalid phase number: %v", err)
		}
		if !d.NextArg() {
			return d.ArgErr()
		}
		action := d.Val()

		if m.ResponseOverride.DefaultActions == nil {
			m.ResponseOverride.DefaultActions = make(map[int]string)
		}
		m.ResponseOverride.DefaultActions[phase] = action

	case "headers":
		if m.ResponseOverride.Headers == nil {
			m.ResponseOverride.Headers = make(map[string]string)
		}
		for d.NextBlock(2) {
			headerName := d.Val()
			if !d.NextArg() {
				return d.Errf("header %s requires a value", headerName)
			}
			headerValue := d.Val()
			m.ResponseOverride.Headers[headerName] = headerValue
		}

	default:
		return d.Errf("unknown response override key: %s", key)
	}

	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m corazaModule
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

func newErrorCb(logger *zap.Logger) func(types.MatchedRule) {
	return func(mr types.MatchedRule) {
		data := mr.ErrorLog()
		switch mr.Rule().Severity() {
		case types.RuleSeverityEmergency:
			logger.Error(data)
		case types.RuleSeverityAlert:
			logger.Error(data)
		case types.RuleSeverityCritical:
			logger.Error(data)
		case types.RuleSeverityError:
			logger.Error(data)
		case types.RuleSeverityWarning:
			logger.Warn(data)
		case types.RuleSeverityNotice:
			logger.Info(data)
		case types.RuleSeverityInfo:
			logger.Info(data)
		case types.RuleSeverityDebug:
			logger.Debug(data)
		}
	}
}

// Interface guards
var (
	_ caddy.Provisioner           = (*corazaModule)(nil)
	_ caddy.Validator             = (*corazaModule)(nil)
	_ caddyhttp.MiddlewareHandler = (*corazaModule)(nil)
	_ caddyfile.Unmarshaler       = (*corazaModule)(nil)
)
