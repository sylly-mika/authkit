package oidc

import "errors"

type flexBool bool

func (b *flexBool) UnmarshalJSON(data []byte) error {
	switch string(data) {
	case "true", `"true"`:
		*b = true
	case "false", `"false"`:
		*b = false
	default:
		return errors.New("oidc: a boolean claim is neither true nor false")
	}
	return nil
}
