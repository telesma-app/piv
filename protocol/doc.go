// Package protocol defines PIV key references, algorithms, data objects, and
// command and response encodings from NIST SP 800-73.
//
// Object parsers accept contents without the outer GET DATA template, except
// where a parser explicitly requires a complete response. Parsing cardholder
// objects and off-card certificate files does not establish their trust.
// EncodeDiscovery and EncodeKeyHistory produce values for PUT DATA without
// changing the caller's supplied policy or certificate locations.
package protocol
