package tests

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sylly-mika/authkit"
	"github.com/sylly-mika/authkit/db"
)

const goodCode = "246810"

var (
	fakeSendID  = uuid.MustParse("6f1c2d3e-4a5b-4c6d-8e7f-900112233445")
	fakeExpires = time.Date(2040, 1, 1, 13, 0, 0, 0, time.UTC)
)

type fakeVerifier struct {
	mu    sync.Mutex
	calls []authkit.FactorKind
	who   []uuid.UUID
}

func (f *fakeVerifier) Verify(ctx context.Context, q db.Querier, principal uuid.UUID, method authkit.FactorKind, code string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, method)
	f.who = append(f.who, principal)
	return code == goodCode, nil
}

func (f *fakeVerifier) RecoveryCodesLeft(ctx context.Context, q db.Querier, principal uuid.UUID) (int, error) {
	return 2, nil
}

func (f *fakeVerifier) SendCode(ctx context.Context, q db.Querier, principal uuid.UUID) (authkit.EmailCodeRequest, time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "send")
	f.who = append(f.who, principal)
	return authkit.EmailCodeRequest{ID: fakeSendID, ExpiresAt: fakeExpires}, 0, nil
}

func (f *fakeVerifier) ChallengeRules() (time.Duration, int) {
	return 5 * time.Minute, 2
}

func (f *fakeVerifier) record() ([]authkit.FactorKind, []uuid.UUID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls), slices.Clone(f.who)
}

func attachFake(w *world) *fakeVerifier {
	w.T.Helper()
	c, err := w.Svc.Attach("secondfactor")
	if err != nil {
		w.T.Fatal(err)
	}
	f := &fakeVerifier{}
	if err := c.SetVerifier(f); err != nil {
		w.T.Fatal(err)
	}
	return f
}

func (w *world) seedTOTP(id uuid.UUID) {
	w.T.Helper()
	w.D.Exec(w.T, `INSERT INTO auth_second_factors (principal_id, kind, secret, created_at, confirmed_at) VALUES ($1, 'totp', '\x01'::bytea, $2, $2)`, id, w.Clock.Now())
}

func (w *world) sessions(id uuid.UUID) int {
	w.T.Helper()
	return w.Count(`SELECT count(*) FROM auth_sessions WHERE principal_id = $1`, id)
}

func (w *world) challenges(id uuid.UUID) int {
	w.T.Helper()
	return w.Count(`SELECT count(*) FROM auth_second_step_challenges WHERE principal_id = $1`, id)
}

func TestSetVerifierTakesOneVerifier(t *testing.T) {
	w := newWorld(t)
	c, err := w.Svc.Attach("secondfactor")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeVerifier{}
	if err := c.SetVerifier(f); err != nil {
		t.Fatalf("first SetVerifier: %v", err)
	}
	if err := c.SetVerifier(f); !errors.Is(err, authkit.ErrAttached) {
		t.Fatalf("second SetVerifier: %v, want ErrAttached", err)
	}

	k := newWorld(t, factors)
	kc, err := k.Svc.Attach("secondfactor")
	if err != nil {
		t.Fatal(err)
	}
	if err := kc.SetVerifier(f); !errors.Is(err, authkit.ErrAttached) {
		t.Fatalf("keyed SetVerifier: %v, want ErrAttached", err)
	}
}

func TestTheGateWaitsForAVerifier(t *testing.T) {
	login := "ada@example.invalid"
	w := newWorld(t)
	ada := w.User(login, pw)
	w.seedTOTP(ada)

	res := w.Login("staff", login, pw)
	if !errors.Is(res.Refusal, authkit.ErrSecondFactorsOff) || res.SecondStep != nil {
		t.Fatalf("without a verifier: refusal %v, second step %v, want ErrSecondFactorsOff", res.Refusal, res.SecondStep)
	}
	if n := w.sessions(ada); n != 0 {
		t.Fatalf("sessions %d without a verifier, want 0", n)
	}
	if n := w.challenges(ada); n != 0 {
		t.Fatalf("challenges %d without a verifier, want 0", n)
	}

	attachFake(w)
	res = w.Login("staff", login, pw)
	if res.Refusal != nil || res.Session != nil || res.SecondStep == nil {
		t.Fatalf("with a verifier: refusal %v, session %v, second step %v", res.Refusal, res.Session, res.SecondStep)
	}
	want := []authkit.FactorKind{authkit.FactorTOTP, authkit.FactorRecovery}
	if !slices.Equal(res.SecondStep.Methods, want) {
		t.Fatalf("methods %v, want %v", res.SecondStep.Methods, want)
	}
	if !res.SecondStep.ExpiresAt.Equal(w.Clock.Now().Add(5 * time.Minute)) {
		t.Fatalf("second step expires at %v, want the verifier's 5 minutes", res.SecondStep.ExpiresAt)
	}
	if n := w.challenges(ada); n != 1 {
		t.Fatalf("challenges %d, want 1", n)
	}
	if n := w.sessions(ada); n != 0 {
		t.Fatalf("sessions %d before the second step, want 0", n)
	}
}

func TestVerifySecondStepTakesTheVerifiersTries(t *testing.T) {
	login := "ada@example.invalid"
	w := newWorld(t)
	ada := w.User(login, pw)
	w.seedTOTP(ada)
	f := attachFake(w)
	tok := w.challenge(login)

	first := w.verify("staff", tok, authkit.FactorTOTP, "000000")
	if !errors.Is(first.Refusal, authkit.ErrBadCode) {
		t.Fatalf("first wrong code: refusal %v, want ErrBadCode", first.Refusal)
	}
	second := w.verify("staff", tok, authkit.FactorTOTP, "000000")
	if !errors.Is(second.Refusal, authkit.ErrChallengeEnded) {
		t.Fatalf("second wrong code: refusal %v, want ErrChallengeEnded", second.Refusal)
	}
	calls, who := f.record()
	if !slices.Equal(calls, []authkit.FactorKind{authkit.FactorTOTP, authkit.FactorTOTP}) {
		t.Fatalf("verifier calls %v, want two totp checks", calls)
	}
	for _, id := range who {
		if id != ada {
			t.Fatalf("verifier checked principal %v, want ada", id)
		}
	}
	if n := w.sessions(ada); n != 0 {
		t.Fatalf("sessions %d after two wrong codes, want 0", n)
	}
}

func TestVerifySecondStepOpensTheSessionThroughTheVerifier(t *testing.T) {
	login := "ada@example.invalid"
	w := newWorld(t)
	ada := w.User(login, pw)
	w.seedTOTP(ada)
	attachFake(w)
	tok := w.challenge(login)

	res := w.verify("staff", tok, authkit.FactorRecovery, goodCode)
	if res.Refusal != nil || res.Session == nil {
		t.Fatalf("recovery sign-in: refusal %v, session %v", res.Refusal, res.Session)
	}
	if res.Session.SecondFactor != "recovery" {
		t.Fatalf("session factor %q, want recovery", res.Session.SecondFactor)
	}
	if res.RecoveryCodesLeft == nil || *res.RecoveryCodesLeft != 2 {
		t.Fatalf("recovery codes left %v, want 2", res.RecoveryCodesLeft)
	}
	if n := w.sessions(ada); n != 1 {
		t.Fatalf("sessions %d, want 1", n)
	}
	if n := w.Count("SELECT count(*) FROM auth_second_step_challenges WHERE principal_id = $1 AND used_at IS NULL", ada); n != 0 {
		t.Fatalf("open challenges %d after the sign-in, want 0", n)
	}
}

func TestSendSecondStepEmailAsksTheVerifier(t *testing.T) {
	login := "ada@example.invalid"
	w := newWorld(t)
	ada := w.User(login, pw)
	w.D.Exec(w.T, "INSERT INTO auth_second_factors (principal_id, kind, created_at, confirmed_at) VALUES ($1, 'email', $2, $2)", ada, w.Clock.Now())
	f := attachFake(w)
	tok := w.challenge(login)

	res := w.InAuth(func(q db.Querier) (authkit.Result, error) {
		return w.Svc.SendSecondStepEmail(w.Ctx, q, "staff", tok, authkit.Meta{})
	})
	if res.Refusal != nil || res.EmailCode == nil {
		t.Fatalf("send: refusal %v, email code %v", res.Refusal, res.EmailCode)
	}
	if res.EmailCode.ID != fakeSendID || !res.EmailCode.ExpiresAt.Equal(fakeExpires) {
		t.Fatalf("email code %v expires %v, want the verifier's", res.EmailCode.ID, res.EmailCode.ExpiresAt)
	}
	calls, who := f.record()
	if !slices.Equal(calls, []authkit.FactorKind{"send"}) {
		t.Fatalf("verifier calls %v, want one send", calls)
	}
	if len(who) != 1 || who[0] != ada {
		t.Fatalf("verifier principals %v, want ada", who)
	}
	if n := w.Count("SELECT count(*) FROM auth_email_codes"); n != 0 {
		t.Fatalf("email code rows %d, want 0 (the verifier writes them)", n)
	}
}
