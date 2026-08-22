package claims

import (
	"fmt"
	"strings"
)

// CustomValidator defines a validation function for a specific claim.
type CustomValidator struct {
	Name     string
	Required bool
	ValidateFn func(value any) error
}

// Registry holds registered custom claim validators.
type Registry struct {
	validators []CustomValidator
}

// NewRegistry creates an empty validator registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds a custom claim validator.
func (r *Registry) Register(v CustomValidator) {
	r.validators = append(r.validators, v)
}

// ValidateAll runs all registered validators against the claims map.
func (r *Registry) ValidateAll(claims map[string]any) []string {
	var issues []string
	for _, v := range r.validators {
		val, exists := claims[v.Name]
		if !exists {
			if v.Required {
				issues = append(issues, fmt.Sprintf("required claim %q missing", v.Name))
			}
			continue
		}
		if v.ValidateFn != nil {
			if err := v.ValidateFn(val); err != nil {
				issues = append(issues, fmt.Sprintf("claim %q: %v", v.Name, err))
			}
		}
	}
	return issues
}

// Count returns the number of registered validators.
func (r *Registry) Count() int {
	return len(r.validators)
}

// --- Common custom validators ---

// StringNotEmpty validates that a claim is a non-empty string.
func StringNotEmpty(name string, required bool) CustomValidator {
	return CustomValidator{
		Name:     name,
		Required: required,
		ValidateFn: func(value any) error {
			s, ok := value.(string)
			if !ok {
				return fmt.Errorf("expected string, got %T", value)
			}
			if s == "" {
				return fmt.Errorf("must not be empty")
			}
			return nil
		},
	}
}

// OneOf validates that a claim value is one of the allowed values.
func OneOf(name string, allowed []string, required bool) CustomValidator {
	return CustomValidator{
		Name:     name,
		Required: required,
		ValidateFn: func(value any) error {
			s, ok := value.(string)
			if !ok {
				return fmt.Errorf("expected string, got %T", value)
			}
			for _, a := range allowed {
				if s == a {
					return nil
				}
			}
			return fmt.Errorf("value %q not in %v", s, allowed)
		},
	}
}

// StringHasPrefix validates that a claim starts with a given prefix.
func StringHasPrefix(name, prefix string, required bool) CustomValidator {
	return CustomValidator{
		Name:     name,
		Required: required,
		ValidateFn: func(value any) error {
			s, ok := value.(string)
			if !ok {
				return fmt.Errorf("expected string, got %T", value)
			}
			if !strings.HasPrefix(s, prefix) {
				return fmt.Errorf("must start with %q", prefix)
			}
			return nil
		},
	}
}

// NumericRange validates that a numeric claim is within [min, max].
func NumericRange(name string, min, max float64, required bool) CustomValidator {
	return CustomValidator{
		Name:     name,
		Required: required,
		ValidateFn: func(value any) error {
			f, ok := asFloat(value)
			if !ok {
				return fmt.Errorf("expected numeric, got %T", value)
			}
			if f < min || f > max {
				return fmt.Errorf("value %g not in [%g, %g]", f, min, max)
			}
			return nil
		},
	}
}

// ArrayContains validates that an array claim contains a specific value.
func ArrayContains(name string, required string, req bool) CustomValidator {
	return CustomValidator{
		Name:     name,
		Required: req,
		ValidateFn: func(value any) error {
			arr, ok := value.([]any)
			if !ok {
				return fmt.Errorf("expected array, got %T", value)
			}
			for _, v := range arr {
				if s, ok := v.(string); ok && s == required {
					return nil
				}
			}
			return fmt.Errorf("array does not contain %q", required)
		},
	}
}
