package authctx

import (
	"context"
	"testing"
)

// TestWithSubject verifies that a subject can be stored and retrieved from context.
func TestWithSubject(t *testing.T) {
	subj := Subject{UserID: "u", TenantID: "t", AAL: 2}
	ctx := WithSubject(context.Background(), subj)
	got, ok := SubjectFromContext(ctx)
	if !ok || got.UserID != "u" || got.TenantID != "t" || got.AAL != 2 {
		t.Fatalf("unexpected subject: %+v", got)
	}
}
