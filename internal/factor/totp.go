package factor

import (
	"bytes"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"image/png"
	"io"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const totpStepSeconds = 30

var totpOpts = totp.ValidateOpts{Period: totpStepSeconds, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}

// Enrolment is what an authenticator app needs to add a secret.
type Enrolment struct {
	URI    string
	Secret string
	QRPNG  []byte
}

// NewSecret reads a 20-byte TOTP secret from r.
func NewSecret(r io.Reader) ([]byte, error) {
	b := make([]byte, 20)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, fmt.Errorf("authkit: random TOTP secret: %w", err)
	}
	return b, nil
}

// VerifyTOTP reports the highest step within one step of now whose code matches and that is later than lastStep.
func VerifyTOTP(secret []byte, code string, now time.Time, lastStep *int64) (step int64, ok bool) {
	code = strings.ReplaceAll(code, " ", "")
	if len(code) != 6 {
		return 0, false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return 0, false
		}
	}
	s := now.Unix() / totpStepSeconds
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	failed := false
	for c := s - 1; c <= s+1; c++ {
		want, err := totp.GenerateCodeCustom(b32, time.Unix(c*totpStepSeconds, 0), totpOpts)
		if err != nil {
			failed = true
			continue
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) != 1 {
			continue
		}
		if lastStep != nil && c <= *lastStep {
			continue
		}
		step, ok = c, true
	}
	if failed {
		return 0, false
	}
	return step, ok
}

// TOTPEnrolment builds the otpauth URI, the base32 secret and a 256x256 PNG QR code for secret.
func TOTPEnrolment(issuer, account string, secret []byte) (Enrolment, error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: account, Period: totpStepSeconds, Secret: secret, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		return Enrolment{}, fmt.Errorf("authkit: TOTP enrolment: %w", err)
	}
	img, err := key.Image(256, 256)
	if err != nil {
		return Enrolment{}, fmt.Errorf("authkit: TOTP enrolment: %w", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return Enrolment{}, fmt.Errorf("authkit: TOTP enrolment: %w", err)
	}
	return Enrolment{URI: key.URL(), Secret: key.Secret(), QRPNG: buf.Bytes()}, nil
}
