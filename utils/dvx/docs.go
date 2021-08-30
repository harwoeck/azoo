// Package dvx provides an easy-to-use interface to a Cryptography service,
// that uses state-of-the-art primitives. It provides 4 main categories of
// supported operations: Encryption/Decryption, Signing/Verifying, MAC, and as
// a special higher-order algorithm: TOTP Creation/Verification.
//
//
// Goals
//
//
// 1. No storage needed
//
// dvx doesn't need any storage, as it derives all internal keys from a root
// secret. This root secret can live inside a hardware-security-module (HSM via
// PKCS#11) or as an alternative be held in a protected RAM section.
//
// 2. Hard to misuse
//
// dvx has an easy-to-use interface and clear separation (boundaries) of
// liabilities.
package dvx
