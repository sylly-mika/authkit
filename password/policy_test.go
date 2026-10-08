package password_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/sylly-mika/authkit/password"
)

func TestPolicyCountsRunesNotBytes(t *testing.T) {
	for _, tc := range []struct {
		pw      string
		ok      bool
		tooLong bool
	}{
		{strings.Repeat("ā", 9), false, false},
		{strings.Repeat("a\u0304", 9), false, false},
		{strings.Repeat("ā", 10), true, false},
		{strings.Repeat("ā", 256), true, false},
		{strings.Repeat("a", 257), false, true},
	} {
		err := password.DefaultPolicy.Check(tc.pw)
		var pe password.PolicyError
		switch {
		case tc.ok && err != nil:
			t.Errorf("%d runes refused: %v", len([]rune(tc.pw)), err)
		case !tc.ok && (!errors.As(err, &pe) || pe.TooLong != tc.tooLong || pe.MinRunes != 10 || pe.MaxRunes != 256):
			t.Errorf("%d runes = %v, want PolicyError{10 256 %v}", len([]rune(tc.pw)), err, tc.tooLong)
		}
	}
}
