package bearer

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
)

// CheckAppClaims refuses app claims that would overwrite a registered one.
func CheckAppClaims(app map[string]any) error {
	for k := range app {
		if slices.Contains(Reserved, k) {
			return fmt.Errorf("%w: %q", ErrReservedClaim, k)
		}
	}
	return nil
}

// Normalize is app claims as a token carries them, after a JSON round trip:
// a uuid.UUID becomes its string and every number a float64.
func Normalize(app map[string]any) (map[string]any, error) {
	out := map[string]any{}
	if len(app) == 0 {
		return out, nil
	}
	b, err := json.Marshal(app)
	if err != nil {
		return nil, fmt.Errorf("authkit: app claims: %w", err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("authkit: app claims: %w", err)
	}
	return out, nil
}

// SameClaims reports whether the claims Admit grants now are exactly the app
// claims a token presented (spec §5.1). An added, removed or changed claim is
// a stale token.
func SameClaims(granted, presented map[string]any) (bool, error) {
	norm, err := Normalize(granted)
	if err != nil {
		return false, err
	}
	if presented == nil {
		presented = map[string]any{}
	}
	return reflect.DeepEqual(norm, presented), nil
}
