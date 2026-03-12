package authctx

import "context"

type Subject struct {
	UserID   string
	TenantID string
	AAL      int
	AuthTime string
}

// WithSubject returns a new context with the given Subject.
func WithSubject(ctx context.Context, s Subject) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, subjectKey{}, s)
}

// SubjectFromContext retrieves the Subject from the context.
func SubjectFromContext(ctx context.Context) (Subject, bool) {
	v := ctx.Value(subjectKey{})
	if v == nil {
		return Subject{}, false
	}
	subj, ok := v.(Subject)
	return subj, ok
}

type subjectKey struct{}
