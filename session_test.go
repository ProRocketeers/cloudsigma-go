package cloudsigma

import (
	"testing"
	"time"
)

func TestTOTP(t *testing.T) {
	// RFC 6238 test vector: ASCII "12345678901234567890" in base32, T=59.
	got, err := TOTP("gezd gnbv gy3t qojq gezd gnbv gy3t qojq", time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got != "287082" {
		t.Errorf("TOTP = %q, want 287082", got)
	}
}
