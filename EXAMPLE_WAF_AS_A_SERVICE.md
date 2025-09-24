# WAF-as-a-Service Integration Example

This document demonstrates how to use the `response_override` feature for WAF-as-a-Service implementations.

## Problem Solved

WAF rule files (CoreRuleSet, OWASP, Comodo, etc.) contain `SecDefaultAction` directives that define default responses. In a WAF-as-a-Service scenario, you need to override these file-based defaults with customer-specific preferences.

## Solution: Response Override

The `response_override` configuration allows you to:
1. **Skip all file-based `SecDefaultAction` directives**
2. **Inject custom `SecDefaultAction` directives** via JSON configuration
3. **Maintain full WAF functionality** without runtime overhead

## JSON Configuration Example

```json
{
  "handler": "waf",
  "load_owasp_crs": true,
  "directives": "SecRuleEngine On\nInclude @coraza.conf-recommended\nInclude @crs-setup.conf.example\nInclude @owasp_crs/*.conf",
  "response_override": {
    "override_file_defaults": true,
    "default_actions": {
      "1": "log,auditlog,deny,status:404",
      "2": "log,auditlog,deny,status:404"
    },
    "headers": {
      "X-WAF-Blocked": "true",
      "X-Customer-ID": "customer123"
    }
  }
}
```

## Caddyfile Configuration Example

```caddyfile
example.com {
    coraza_waf {
        load_owasp_crs
        directives `
            SecRuleEngine On
            Include @coraza.conf-recommended
            Include @crs-setup.conf.example
            Include @owasp_crs/*.conf
        `
        response_override {
            override_file_defaults
            default_action 1 "log,auditlog,deny,status:404"
            default_action 2 "log,auditlog,deny,status:404"
            headers {
                X-WAF-Blocked "true"
                X-Customer-ID "customer123"
            }
        }
    }
    reverse_proxy backend:8080
}
```

## How It Works

### 1. File Processing
When `override_file_defaults: true` is set:
- **Before**: WAF loads rules with file-based `SecDefaultAction "phase:1,log,auditlog,deny,status:403"`
- **After**: File-based `SecDefaultAction` directives are filtered out
- **Result**: Only your custom actions are used

### 2. Custom Action Injection
Your custom `default_actions` are injected as `SecDefaultAction` directives:
```
SecDefaultAction "phase:1,log,auditlog,deny,status:404"
SecDefaultAction "phase:2,log,auditlog,deny,status:404"
```

### 3. Customer-Specific Responses
Different customers can have different response behaviors:

**Customer A** (404 responses):
```json
{
  "response_override": {
    "override_file_defaults": true,
    "default_actions": {
      "1": "log,auditlog,deny,status:404",
      "2": "log,auditlog,deny,status:404"
    }
  }
}
```

**Customer B** (redirect responses):
```json
{
  "response_override": {
    "override_file_defaults": true,
    "default_actions": {
      "1": "log,auditlog,redirect:'https://customer-b.com/blocked'",
      "2": "log,auditlog,redirect:'https://customer-b.com/blocked'"
    }
  }
}
```

**Customer C** (drop connections):
```json
{
  "response_override": {
    "override_file_defaults": true,
    "default_actions": {
      "1": "log,auditlog,drop",
      "2": "log,auditlog,drop"
    }
  }
}
```

## WAF-as-a-Service Implementation

### 1. Customer Configuration Management
```go
type CustomerWAFConfig struct {
    CustomerID       string            `json:"customer_id"`
    ResponseType     string            `json:"response_type"` // "404", "403", "redirect", "drop"
    RedirectURL      string            `json:"redirect_url,omitempty"`
    CustomHeaders    map[string]string `json:"custom_headers,omitempty"`
}

func generateCaddyConfig(customer CustomerWAFConfig) map[string]interface{} {
    config := map[string]interface{}{
        "handler": "waf",
        "load_owasp_crs": true,
        "directives": "SecRuleEngine On\nInclude @coraza.conf-recommended\nInclude @crs-setup.conf.example\nInclude @owasp_crs/*.conf",
        "response_override": map[string]interface{}{
            "override_file_defaults": true,
            "default_actions": generateDefaultActions(customer.ResponseType, customer.RedirectURL),
            "headers": customer.CustomHeaders,
        },
    }
    return config
}

func generateDefaultActions(responseType, redirectURL string) map[string]string {
    actions := make(map[string]string)
    
    switch responseType {
    case "404":
        actions["1"] = "log,auditlog,deny,status:404"
        actions["2"] = "log,auditlog,deny,status:404"
    case "403":
        actions["1"] = "log,auditlog,deny,status:403"
        actions["2"] = "log,auditlog,deny,status:403"
    case "redirect":
        if redirectURL != "" {
            actions["1"] = fmt.Sprintf("log,auditlog,redirect:'%s'", redirectURL)
            actions["2"] = fmt.Sprintf("log,auditlog,redirect:'%s'", redirectURL)
        }
    case "drop":
        actions["1"] = "log,auditlog,drop"
        actions["2"] = "log,auditlog,drop"
    }
    
    return actions
}
```

### 2. Dynamic Configuration Updates
```go
func updateCustomerWAFConfig(customerID string, newConfig CustomerWAFConfig) error {
    // Generate new Caddy configuration
    caddyConfig := generateCaddyConfig(newConfig)
    
    // Post to Caddy admin API
    return postToCaddyAPI(fmt.Sprintf("/config/apps/http/servers/srv0/routes/0/handle/0"), caddyConfig)
}
```

## Benefits

### ✅ **Minimal Impact**
- No complex response interception
- No runtime performance overhead
- Clean, predictable behavior

### ✅ **Full Control**
- Override any file-based `SecDefaultAction`
- Customer-specific response behavior
- Maintain all WAF protection

### ✅ **Scalable**
- Easy to manage thousands of customers
- Simple JSON configuration
- No file system changes needed

### ✅ **Backward Compatible**
- Existing setups work unchanged
- Optional feature activation
- No breaking changes

## Migration from File-Based Approach

### Before (File-Based)
```
# In WAF rule files
SecDefaultAction "phase:1,log,auditlog,deny,status:403"
SecDefaultAction "phase:2,log,auditlog,deny,status:403"
```

### After (WAF-as-a-Service)
```json
{
  "response_override": {
    "override_file_defaults": true,
    "default_actions": {
      "1": "log,auditlog,deny,status:404",
      "2": "log,auditlog,deny,status:404"
    }
  }
}
```

The file-based actions are automatically filtered out and replaced with your custom ones.

## Testing

Run the included tests to verify functionality:
```bash
go test -v -run TestProcessDirectives
go test -v -run TestGenerateCustomDefaultActions
go test -v -run TestIntegrationOverrideFlow
```
