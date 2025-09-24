package coraza

import (
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestProcessDirectives(t *testing.T) {
	tests := []struct {
		name       string
		override   *ResponseOverride
		directives string
		expected   string
	}{
		{
			name:       "no override - directives unchanged",
			override:   nil,
			directives: "SecRuleEngine On\nSecDefaultAction \"phase:1,log,deny,status:403\"\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,deny\"",
			expected:   "SecRuleEngine On\nSecDefaultAction \"phase:1,log,deny,status:403\"\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,deny\"",
		},
		{
			name: "override disabled - directives unchanged",
			override: &ResponseOverride{
				OverrideFileDefaults: false,
			},
			directives: "SecRuleEngine On\nSecDefaultAction \"phase:1,log,deny,status:403\"\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,deny\"",
			expected:   "SecRuleEngine On\nSecDefaultAction \"phase:1,log,deny,status:403\"\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,deny\"",
		},
		{
			name: "override enabled - SecDefaultAction filtered out",
			override: &ResponseOverride{
				OverrideFileDefaults: true,
			},
			directives: "SecRuleEngine On\nSecDefaultAction \"phase:1,log,deny,status:403\"\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,deny\"",
			expected:   "SecRuleEngine On\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,deny\"",
		},
		{
			name: "multiple SecDefaultAction lines filtered",
			override: &ResponseOverride{
				OverrideFileDefaults: true,
			},
			directives: "SecRuleEngine On\nSecDefaultAction \"phase:1,log,deny,status:403\"\nSecDefaultAction \"phase:2,log,deny,status:404\"\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,deny\"",
			expected:   "SecRuleEngine On\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,deny\"",
		},
		{
			name: "case insensitive filtering",
			override: &ResponseOverride{
				OverrideFileDefaults: true,
			},
			directives: "SecRuleEngine On\nsecdefaultaction \"phase:1,log,deny,status:403\"\nSECDEFAULTACTION \"phase:2,log,deny,status:404\"\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,deny\"",
			expected:   "SecRuleEngine On\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,deny\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &corazaModule{
				ResponseOverride: tt.override,
			}

			result := m.processDirectives(tt.directives)
			if result != tt.expected {
				t.Errorf("Expected:\n%s\nGot:\n%s", tt.expected, result)
			}
		})
	}
}

func TestGenerateCustomDefaultActions(t *testing.T) {
	tests := []struct {
		name     string
		override *ResponseOverride
		expected string
	}{
		{
			name:     "nil override",
			override: nil,
			expected: "",
		},
		{
			name: "empty default actions",
			override: &ResponseOverride{
				OverrideFileDefaults: true,
				DefaultActions:       map[int]string{},
			},
			expected: "",
		},
		{
			name: "single phase action",
			override: &ResponseOverride{
				OverrideFileDefaults: true,
				DefaultActions: map[int]string{
					1: "log,auditlog,deny,status:404",
				},
			},
			expected: "SecDefaultAction \"phase:1,log,auditlog,deny,status:404\"",
		},
		{
			name: "multiple phase actions",
			override: &ResponseOverride{
				OverrideFileDefaults: true,
				DefaultActions: map[int]string{
					1: "log,auditlog,deny,status:404",
					2: "log,auditlog,deny,status:404",
				},
			},
			expected: "SecDefaultAction \"phase:1,log,auditlog,deny,status:404\"\nSecDefaultAction \"phase:2,log,auditlog,deny,status:404\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &corazaModule{
				ResponseOverride: tt.override,
			}

			result := m.generateCustomDefaultActions()

			// Since map iteration order is not guaranteed, we need to check both possible orders
			if tt.override != nil && len(tt.override.DefaultActions) > 1 {
				// For multiple actions, check if all expected lines are present
				expectedLines := strings.Split(tt.expected, "\n")
				resultLines := strings.Split(result, "\n")

				if len(expectedLines) != len(resultLines) {
					t.Errorf("Expected %d lines, got %d", len(expectedLines), len(resultLines))
					return
				}

				for _, expectedLine := range expectedLines {
					found := false
					for _, resultLine := range resultLines {
						if expectedLine == resultLine {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected line not found: %s", expectedLine)
					}
				}
			} else {
				// For single or no actions, exact match is fine
				if result != tt.expected {
					t.Errorf("Expected:\n%s\nGot:\n%s", tt.expected, result)
				}
			}
		})
	}
}

func TestCaddyfileResponseOverrideParsing(t *testing.T) {
	input := `coraza_waf {
		load_owasp_crs
		directives "SecRuleEngine On"
		response_override {
			override_file_defaults
			default_action 1 "log,auditlog,deny,status:404"
			default_action 2 "log,auditlog,deny,status:404"
			headers {
				X-Blocked "true"
				X-Custom "value"
			}
		}
	}`

	d := caddyfile.NewTestDispenser(input)
	m := &corazaModule{}

	err := m.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("Failed to parse Caddyfile: %v", err)
	}

	if m.ResponseOverride == nil {
		t.Fatal("Expected response_override to be parsed")
	}

	if !m.ResponseOverride.OverrideFileDefaults {
		t.Error("Expected override_file_defaults to be true")
	}

	if len(m.ResponseOverride.DefaultActions) != 2 {
		t.Errorf("Expected 2 default actions, got %d", len(m.ResponseOverride.DefaultActions))
	}

	if m.ResponseOverride.DefaultActions[1] != "log,auditlog,deny,status:404" {
		t.Errorf("Expected phase 1 action 'log,auditlog,deny,status:404', got '%s'", m.ResponseOverride.DefaultActions[1])
	}

	if m.ResponseOverride.DefaultActions[2] != "log,auditlog,deny,status:404" {
		t.Errorf("Expected phase 2 action 'log,auditlog,deny,status:404', got '%s'", m.ResponseOverride.DefaultActions[2])
	}

	if len(m.ResponseOverride.Headers) != 2 {
		t.Errorf("Expected 2 headers, got %d", len(m.ResponseOverride.Headers))
	}

	if m.ResponseOverride.Headers["X-Blocked"] != "true" {
		t.Errorf("Expected X-Blocked header 'true', got '%s'", m.ResponseOverride.Headers["X-Blocked"])
	}
}

func TestIntegrationOverrideFlow(t *testing.T) {
	// Test the complete flow: filter file-based SecDefaultAction and add custom ones
	m := &corazaModule{
		Directives: `SecRuleEngine On
SecDefaultAction "phase:1,log,auditlog,deny,status:403"
SecDefaultAction "phase:2,log,auditlog,deny,status:403"
SecRule REQUEST_URI "@streq /admin" "id:101,phase:1,deny"`,
		ResponseOverride: &ResponseOverride{
			OverrideFileDefaults: true,
			DefaultActions: map[int]string{
				1: "log,auditlog,deny,status:404",
				2: "log,auditlog,deny,status:404",
			},
		},
	}

	// Process directives (should filter out SecDefaultAction)
	processedDirectives := m.processDirectives(m.Directives)
	expectedProcessed := `SecRuleEngine On
SecRule REQUEST_URI "@streq /admin" "id:101,phase:1,deny"`

	if processedDirectives != expectedProcessed {
		t.Errorf("Expected processed directives:\n%s\nGot:\n%s", expectedProcessed, processedDirectives)
	}

	// Generate custom directives
	customDirectives := m.generateCustomDefaultActions()

	// Should contain both phase 1 and phase 2 custom actions
	if !strings.Contains(customDirectives, "SecDefaultAction \"phase:1,log,auditlog,deny,status:404\"") {
		t.Error("Expected custom directives to contain phase 1 action")
	}

	if !strings.Contains(customDirectives, "SecDefaultAction \"phase:2,log,auditlog,deny,status:404\"") {
		t.Error("Expected custom directives to contain phase 2 action")
	}
}

func TestJSONConfigurationExample(t *testing.T) {
	// This test demonstrates how your WAF-as-a-Service would configure the module via JSON
	expectedConfig := &corazaModule{
		LoadOWASPCRS: true,
		Directives: `SecRuleEngine On
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf`,
		ResponseOverride: &ResponseOverride{
			OverrideFileDefaults: true,
			DefaultActions: map[int]string{
				1: "log,auditlog,deny,status:404",
				2: "log,auditlog,deny,status:404",
			},
			Headers: map[string]string{
				"X-WAF-Blocked": "true",
				"X-Customer-ID": "customer123",
			},
		},
	}

	// Verify the configuration would work as expected
	if !expectedConfig.ResponseOverride.OverrideFileDefaults {
		t.Error("Expected override to be enabled")
	}

	if len(expectedConfig.ResponseOverride.DefaultActions) != 2 {
		t.Error("Expected 2 custom default actions")
	}

	// Test that file-based SecDefaultAction would be filtered
	testDirectives := `SecRuleEngine On
SecDefaultAction "phase:1,log,auditlog,deny,status:403"
Include @owasp_crs/*.conf`

	processed := expectedConfig.processDirectives(testDirectives)
	if strings.Contains(processed, "SecDefaultAction") {
		t.Error("Expected SecDefaultAction to be filtered out")
	}
}
