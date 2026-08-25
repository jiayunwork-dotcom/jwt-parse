package claims

import (
	"fmt"
	"strings"
)

type CustomValidator struct {
	Name       string
	Required   bool
	ValidateFn func(value any) error
}

type Registry struct {
	validators []CustomValidator
}

func NewRegistry() *Registry {
	return &Registry{}
}

func (r *Registry) Register(v CustomValidator) {
	r.validators = append(r.validators, v)
}

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

func (r *Registry) Count() int {
	return len(r.validators)
}

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
