package coraza

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestProcessDirectivesSimplified(t *testing.T) {
	tests := []struct {
		name       string
		override   *ResponseOverride
		directives string
		expected   string
	}{
		{
			name:       "no_override_directives_unchanged",
			override:   nil,
			directives: "SecRuleEngine On\nSecDefaultAction \"phase:1,log,auditlog,deny,status:403\"\nSecRule REQUEST_URI \"test\" \"id:1,deny\"",
			expected:   "SecRuleEngine On\nSecDefaultAction \"phase:1,log,auditlog,deny,status:403\"\nSecRule REQUEST_URI \"test\" \"id:1,deny\"",
		},
		{
			name: "override_disabled_directives_unchanged",
			override: &ResponseOverride{
				OverrideFileDefaults: false,
			},
			directives: "SecRuleEngine On\nSecDefaultAction \"phase:1,log,auditlog,deny,status:403\"\nSecRule REQUEST_URI \"test\" \"id:1,deny\"",
			expected:   "SecRuleEngine On\nSecDefaultAction \"phase:1,log,auditlog,deny,status:403\"\nSecRule REQUEST_URI \"test\" \"id:1,deny\"",
		},
		{
			name: "override_enabled_inline_SecDefaultAction_preserved",
			override: &ResponseOverride{
				OverrideFileDefaults: true,
			},
			directives: "SecRuleEngine On\nSecDefaultAction \"phase:1,log,auditlog,deny,status:403\"\nSecRule REQUEST_URI \"test\" \"id:1,deny\"",
			expected:   "SecRuleEngine On\nSecDefaultAction \"phase:1,log,auditlog,deny,status:403\"\nSecRule REQUEST_URI \"test\" \"id:1,deny\"",
		},
		{
			name: "multiple_inline_SecDefaultAction_preserved",
			override: &ResponseOverride{
				OverrideFileDefaults: true,
			},
			directives: "SecRuleEngine On\nSecDefaultAction \"phase:1,log,auditlog,deny,status:403\"\nSecRule REQUEST_URI \"test\" \"id:1,deny\"\nSecDefaultAction \"phase:2,log,auditlog,deny,status:403\"",
			expected:   "SecRuleEngine On\nSecDefaultAction \"phase:1,log,auditlog,deny,status:403\"\nSecRule REQUEST_URI \"test\" \"id:1,deny\"\nSecDefaultAction \"phase:2,log,auditlog,deny,status:403\"",
		},
		{
			name: "inline_SecDefaultAction_preserved_case_insensitive",
			override: &ResponseOverride{
				OverrideFileDefaults: true,
			},
			directives: "SecRuleEngine On\nsecdefaultaction \"phase:1,log,auditlog,deny,status:403\"\nSecRule REQUEST_URI \"test\" \"id:1,deny\"\nSECDEFAULTACTION \"phase:2,log,auditlog,deny,status:403\"",
			expected:   "SecRuleEngine On\nsecdefaultaction \"phase:1,log,auditlog,deny,status:403\"\nSecRule REQUEST_URI \"test\" \"id:1,deny\"\nSECDEFAULTACTION \"phase:2,log,auditlog,deny,status:403\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &corazaModule{
				ResponseOverride: tt.override,
			}

			result := m.processDirectives(tt.directives)
			if result != tt.expected {
				t.Errorf("Expected:\n%s\n\nGot:\n%s", tt.expected, result)
			}
		})
	}
}

func TestIncludeDirectiveProcessingSimplified(t *testing.T) {
	// Create temporary test file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test_rules.conf")
	testContent := `SecDefaultAction "phase:1,deny,status:403,msg:'File default'"
SecRule REQUEST_URI "@contains attack" "id:6001,phase:1,block,msg:'Attack detected'"
SecDefaultAction "phase:2,deny,status:403,msg:'Another file default'"
SecRule ARGS "@contains injection" "id:6002,phase:2,block,msg:'Injection detected'"`
	
	err := os.WriteFile(testFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	tests := []struct {
		name             string
		directives       string
		responseOverride *ResponseOverride
		expectFiltered   bool
		description      string
	}{
		{
			name:             "include_without_override",
			directives:       `Include ` + testFile,
			responseOverride: nil,
			expectFiltered:   false,
			description:      "Include without override should preserve Include directive",
		},
		{
			name: "include_with_override",
			directives: `Include ` + testFile,
			responseOverride: &ResponseOverride{
				OverrideFileDefaults: true,
			},
			expectFiltered: true,
			description:    "Include with override should filter SecDefaultAction",
		},
		{
			name: "mixed_inline_and_include",
			directives: `SecDefaultAction "phase:1,deny,status:403,msg:'Inline default'"
Include ` + testFile + `
SecRule REQUEST_URI "@contains inline" "id:7001,phase:1,block,msg:'Inline rule'"`,
			responseOverride: &ResponseOverride{
				OverrideFileDefaults: true,
			},
			expectFiltered: false, // Inline SecDefaultAction should be preserved
			description:    "Mixed inline and include should preserve inline SecDefaultAction but filter file-based ones",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &corazaModule{
				Directives:       tt.directives,
				ResponseOverride: tt.responseOverride,
			}

			// Process directives
			processed := m.processDirectives(tt.directives)
			
			// Check for SecDefaultAction
			hasSecDefault := strings.Contains(strings.ToLower(processed), "secdefaultaction")
			
			if tt.expectFiltered {
				// For include_with_override: SecDefaultAction from files should be filtered
				if hasSecDefault {
					t.Errorf("Expected file-based SecDefaultAction to be filtered, but found in: %s", processed)
				}
				// When filtering, rules should be expanded from included files
				if !strings.Contains(processed, "6001") {
					t.Errorf("Expected rule 6001 to be preserved in: %s", processed)
				}
				if !strings.Contains(processed, "6002") {
					t.Errorf("Expected rule 6002 to be preserved in: %s", processed)
				}
			} else {
				if tt.name == "include_without_override" {
					// Without override, the Include directive should be preserved as-is
					if !strings.Contains(processed, "Include") {
						t.Errorf("Expected Include directive to be preserved, but not found in: %s", processed)
					}
				} else if tt.name == "mixed_inline_and_include" {
					// For mixed case: inline SecDefaultAction should be preserved
					if !strings.Contains(processed, `SecDefaultAction "phase:1,deny,status:403,msg:'Inline default'"`) {
						t.Errorf("Expected inline SecDefaultAction to be preserved, but not found in: %s", processed)
					}
					// Rules from included files should be expanded and preserved
					if !strings.Contains(processed, "6001") {
						t.Errorf("Expected rule 6001 to be preserved in: %s", processed)
					}
					if !strings.Contains(processed, "6002") {
						t.Errorf("Expected rule 6002 to be preserved in: %s", processed)
					}
					// File-based SecDefaultAction should be filtered out (not present)
					fileSecDefaultCount := strings.Count(strings.ToLower(processed), "secdefaultaction")
					if fileSecDefaultCount != 1 { // Only the inline one should remain
						t.Errorf("Expected only 1 SecDefaultAction (inline), but found %d in: %s", fileSecDefaultCount, processed)
					}
				}
			}

			t.Logf("✅ %s: Test passed", tt.description)
		})
	}
}

func TestCaddyfileResponseOverrideParsingSimplified(t *testing.T) {
	input := `coraza_waf {
		directives "SecRuleEngine On"
		response_override {
			override_file_defaults
		}
	}`

	d := caddyfile.NewTestDispenser(input)
	m := &corazaModule{}
	err := m.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("Failed to parse Caddyfile: %v", err)
	}

	if m.ResponseOverride == nil {
		t.Fatal("Expected ResponseOverride to be set")
	}

	if !m.ResponseOverride.OverrideFileDefaults {
		t.Error("Expected OverrideFileDefaults to be true")
	}
}

func TestJSONConfigurationExampleSimplified(t *testing.T) {
	// This test demonstrates the simplified approach where WAF-as-a-Service
	// injects SecDefaultAction directly in the directives string
	
	// Example of what the WAF-as-a-Service would generate
	directives := `SecRuleEngine On
Include /path/to/rules/*.conf
SecDefaultAction "phase:1,deny,status:404,msg:'Not Found'"
SecDefaultAction "phase:2,deny,status:301,redirect:'https://blocked.example.com'"`

	config := &corazaModule{
		Directives: directives,
		ResponseOverride: &ResponseOverride{
			OverrideFileDefaults: true, // This filters out file-based SecDefaultAction
		},
	}

	// Process the directives
	processed := config.processDirectives(config.Directives)
	
	// Should contain the custom SecDefaultAction (injected by WAF-as-a-Service)
	if !strings.Contains(processed, `SecDefaultAction "phase:1,deny,status:404,msg:'Not Found'"`) {
		t.Error("Expected custom phase 1 SecDefaultAction to be preserved")
	}
	
	if !strings.Contains(processed, `SecDefaultAction "phase:2,deny,status:301,redirect:'https://blocked.example.com'"`) {
		t.Error("Expected custom phase 2 SecDefaultAction to be preserved")
	}

	t.Logf("✅ JSON configuration example test passed")
}
