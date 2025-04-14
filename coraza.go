// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"errors"
	"net/http"
	"path/filepath"
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

// corazaModule is a Web Application Firewall implementation for Caddy.
type corazaModule struct {
	// deprecated
	Include      []string `json:"include"`
	Directives   string   `json:"directives"`
	LoadOWASPCRS bool     `json:"load_owasp_crs"`

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
		WithErrorCallback(newErrorCb(m.logger)).
		WithDebugLogger(newLogger(m.logger))

	if m.LoadOWASPCRS {
		config = config.WithRootFS(mergefs.Merge(coreruleset.FS, io.OSFS))
	}

	// Always ensure we have some directives
	if m.Directives == "" {
		m.Directives = `
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecRule REQUEST_URI "@streq /blocked" "id:1,phase:1,deny,status:403"
`
	}

	config = config.WithDirectives(m.Directives)

	// Handle deprecated include field
	if len(m.Include) > 0 {
		m.logger.Warn("'include' field is deprecated, please use the Include directive inside 'directives' field instead")
		for _, file := range m.Include {
			if strings.Contains(file, "*") {
				m.logger.Debug("Preparing to expand glob", zap.String("pattern", file))
				fs, err := filepath.Glob(file)
				if err != nil {
					return err
				}
				for _, f := range fs {
					config = config.WithDirectivesFromFile(f)
				}
			} else {
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

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m corazaModule) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	id := randomString(16)
	tx := m.waf.NewTransactionWithID(id)
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	repl.Set("http.transaction_id", id)

	// ProcessRequest is just a wrapper around ProcessConnection, ProcessURI,
	// ProcessRequestHeaders and ProcessRequestBody.
	if it, err := processRequest(tx, r); err != nil {
		return caddyhttp.HandlerError{
			StatusCode: http.StatusInternalServerError,
			ID:         tx.ID(),
			Err:        err,
		}
	} else if it != nil {
		w.WriteHeader(obtainStatusCodeFromInterruptionOrDefault(it, http.StatusForbidden))
		return nil
	}

	ww, processResponse := wrap(w, r, tx)

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
		default:
			return d.Errf("invalid key %q", key)
		}
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
		logMsg := mr.ErrorLog()
		switch mr.Rule().Severity() {
		case types.RuleSeverityEmergency,
			types.RuleSeverityAlert,
			types.RuleSeverityCritical,
			types.RuleSeverityError:
			logger.Error(logMsg)
		case types.RuleSeverityWarning:
			logger.Warn(logMsg)
		case types.RuleSeverityNotice:
			logger.Info(logMsg)
		case types.RuleSeverityInfo:
			logger.Info(logMsg)
		case types.RuleSeverityDebug:
			logger.Debug(logMsg)
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
