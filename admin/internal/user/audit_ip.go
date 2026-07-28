package user

import "context"

// The client IP behind an audited action travels in the request context rather
// than as a Record() parameter.
//
// Record has ~30 call sites across the handlers.  Threading an ip argument
// through all of them would work today and rot tomorrow: the failure mode of a
// new call site that forgets it is a silent hole in the audit trail, which is
// the one property an audit trail cannot have.  Reading it from the context
// means the middleware that already resolves the IP fills it in once, and every
// action -- including ones written later -- is covered by construction.
//
// A caller with no request behind it (CLI, cron, the setup wizard before the
// middleware runs) records a nil IP, which is honest: there was no client.

type clientIPKey struct{}

// WithClientIP returns a context carrying the IP an audited action came from.
func WithClientIP(ctx context.Context, ip string) context.Context {
	if ip == "" {
		return ctx
	}
	return context.WithValue(ctx, clientIPKey{}, ip)
}

// ClientIPFromContext reports the IP stored by WithClientIP, or "" if none.
func ClientIPFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(clientIPKey{}).(string)
	return v
}
