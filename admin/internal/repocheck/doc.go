// Package repocheck contains no code -- only tests that assert repository
// invariants: pairs of files that must agree, where nothing at build time
// notices when they drift apart.
//
// Kept out of the functional packages on purpose.  A check about the CI
// workflow living in internal/settings is findable only by accident, and
// reads as if it were about settings.
package repocheck
