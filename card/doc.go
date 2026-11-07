// Package card provides owned PIV card sessions over initialized transports.
//
// New takes ownership of a transport on which PIV is already selected. The
// caller must stop using it directly. Device serializes complete operations;
// separate calls do not form an atomic workflow.
//
// Waiting for an operation respects its context. Close prevents new operations,
// releases waiting callers, and closes the transport without acquiring the
// operation gate. Interrupting active I/O depends on the transport. A
// transport.DeviceInvalidatedError closes the session; subsequent operations
// return io.ErrClosedPipe. Cancellation before an operation starts preserves
// the session, and a completed response is not replaced by a later cancellation.
//
// Device does not retry commands or cache certificates, authentication state,
// PINs, or administration keys. Application discovery and certificate trust
// evaluation belong to the caller.
//
// With SCP11b, unauthenticated status words, including unsigned card errors,
// invalidate the channel. Device does not reconnect or downgrade to plaintext.
package card
