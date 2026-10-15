package totp_test

import (
	"bytes"
	"encoding/base32"
	"image/png"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	pqtotp "github.com/pquerna/otp/totp"

	"github.com/sylly-mika/authkit/internal/totp"
)

var opts = pqtotp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

var rfcSecret = []byte("12345678901234567890")

func seq(from, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(from + i)
	}
	return b
}

func at(sec int64) time.Time { return time.Unix(sec, 0).UTC() }

func TestNewSecretIs20BytesOfTheReader(t *testing.T) {
	got, err := totp.NewSecret(bytes.NewReader(seq(0, 40)))
	if err != nil || !bytes.Equal(got, seq(0, 20)) {
		t.Errorf("NewSecret = <redacted>, %v, want the first 20 bytes of the reader, nil", err)
	}
	short, err := totp.NewSecret(bytes.NewReader(seq(0, 19)))
	if short != nil || err == nil {
		t.Errorf("NewSecret on 19 bytes = <redacted>, %v, want nil and an error", err)
	}
}

func TestVerifyTOTPMatchesTheRFCVectors(t *testing.T) {
	if step, ok := totp.VerifyTOTP(rfcSecret, "287082", at(59), nil); step != 1 || !ok {
		t.Errorf("VerifyTOTP(<redacted>) at 59 = %d, %v, want 1, true", step, ok)
	}
	if step, ok := totp.VerifyTOTP(rfcSecret, "081804", at(1111111109), nil); step != 37037036 || !ok {
		t.Errorf("VerifyTOTP(<redacted>) at 1111111109 = %d, %v, want 37037036, true", step, ok)
	}
}

func TestVerifyTOTPAcceptsOneStepOfDriftEitherWay(t *testing.T) {
	for _, c := range []struct {
		code string
		step int64
	}{{"969429", 3}, {"338314", 4}, {"254676", 5}} {
		if step, ok := totp.VerifyTOTP(rfcSecret, c.code, at(125), nil); step != c.step || !ok {
			t.Errorf("VerifyTOTP(<redacted>) at 125 = %d, %v, want %d, true", step, ok, c.step)
		}
	}
}

func TestVerifyTOTPRefusesTwoStepsOfDrift(t *testing.T) {
	for _, code := range []string{"359152", "287922"} {
		if step, ok := totp.VerifyTOTP(rfcSecret, code, at(125), nil); step != 0 || ok {
			t.Errorf("VerifyTOTP(<redacted>) at 125 = %d, %v, want 0, false", step, ok)
		}
	}
}

func TestVerifyTOTPRefusesAStepAlreadyUsed(t *testing.T) {
	last := func(v int64) *int64 { return &v }
	for _, c := range []struct {
		name     string
		code     string
		lastStep *int64
		step     int64
		ok       bool
	}{
		{"same step again", "338314", last(4), 0, false},
		{"previous step", "338314", last(3), 4, true},
		{"earlier step", "969429", last(3), 0, false},
		{"next step after use", "254676", last(4), 5, true},
	} {
		if step, ok := totp.VerifyTOTP(rfcSecret, c.code, at(125), c.lastStep); step != c.step || ok != c.ok {
			t.Errorf("%s: VerifyTOTP(<redacted>) at 125 = %d, %v, want %d, %v", c.name, step, ok, c.step, c.ok)
		}
	}
}

func TestVerifyTOTPTakesSpacesAndRefusesMalformedCodes(t *testing.T) {
	for _, code := range []string{"338 314", " 338314 "} {
		if step, ok := totp.VerifyTOTP(rfcSecret, code, at(125), nil); step != 4 || !ok {
			t.Errorf("VerifyTOTP(<redacted>) at 125 = %d, %v, want 4, true", step, ok)
		}
	}
	for _, code := range []string{"", "33831", "3383140", "33831a", "３３８３１４", "-38314"} {
		if step, ok := totp.VerifyTOTP(rfcSecret, code, at(125), nil); step != 0 || ok {
			t.Errorf("VerifyTOTP(<redacted>) at 125 = %d, %v, want 0, false", step, ok)
		}
	}
}

func TestVerifyTOTPRefusesAnotherSecretsCode(t *testing.T) {
	other := seq(100, 20)
	if step, ok := totp.VerifyTOTP(other, "338314", at(125), nil); step != 0 || ok {
		t.Errorf("VerifyTOTP with another secret's code = %d, %v, want 0, false", step, ok)
	}
	code, err := pqtotp.GenerateCodeCustom(b32.EncodeToString(other), at(125), opts)
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}
	if step, ok := totp.VerifyTOTP(other, code, at(125), nil); step != 4 || !ok {
		t.Errorf("VerifyTOTP(<redacted>) with its own code = %d, %v, want 4, true", step, ok)
	}
}

func TestTOTPEnrolmentBuildsTheURIAndAQRCode(t *testing.T) {
	e, err := totp.TOTPEnrolment("Ino Tasks", "ada@example.invalid", rfcSecret)
	if err != nil {
		t.Fatalf("TOTPEnrolment: %v", err)
	}
	const wantSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if e.Secret != wantSecret {
		t.Errorf("Enrolment.Secret = <redacted>, want the base32 of the secret")
	}
	u, err := url.Parse(e.URI)
	if err != nil {
		t.Fatalf("url.Parse(<redacted>): %v", err)
	}
	q := u.Query()
	if u.Scheme != "otpauth" || u.Host != "totp" || u.Path != "/Ino Tasks:ada@example.invalid" {
		t.Errorf("URI scheme, host and path = %q, %q, %q, want otpauth, totp, /Ino Tasks:ada@example.invalid", u.Scheme, u.Host, u.Path)
	}
	if q.Get("secret") != e.Secret || q.Get("issuer") != "Ino Tasks" || q.Get("period") != "30" || q.Get("algorithm") != "SHA1" || q.Get("digits") != "6" {
		t.Errorf("URI query = <redacted>, want the secret, issuer=Ino Tasks, period=30, algorithm=SHA1, digits=6")
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(e.QRPNG))
	if err != nil || cfg.Width != 256 || cfg.Height != 256 {
		t.Errorf("QR PNG = %v, %dx%d, want 256x256", err, cfg.Width, cfg.Height)
	}
	code, err := pqtotp.GenerateCodeCustom(e.Secret, at(1700000000), opts)
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}
	if _, ok := totp.VerifyTOTP(rfcSecret, code, at(1700000000), nil); !ok {
		t.Errorf("a code from the enrolment's secret is refused by VerifyTOTP: <redacted>")
	}
}

func TestTOTPEnrolmentRefusesAnEmptyAccount(t *testing.T) {
	e, err := totp.TOTPEnrolment("Ino Tasks", "", rfcSecret)
	if e.URI != "" || e.QRPNG != nil {
		t.Errorf("TOTPEnrolment with an empty account returned a non-zero Enrolment: <redacted>")
	}
	if err == nil || !strings.HasPrefix(err.Error(), "authkit: TOTP enrolment: ") {
		t.Errorf("TOTPEnrolment error = %v, want the text authkit: TOTP enrolment: ...", err)
	}
}
