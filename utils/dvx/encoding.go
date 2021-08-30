package dvx

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// TypePrefix is a string defining the prefix of the encoded dvx string
type TypePrefix string

const (
	// Encrypted is the TypePrefix for encrypted content
	Encrypted TypePrefix = "enc"
	// Signed is the TypePrefix for a signature
	Signed TypePrefix = "sig"
	// Tagged is the TypePrefix for a MAC
	Tagged TypePrefix = "tag"
	// TOTP is the TypePrefix for a TOTP selector id
	TOTP TypePrefix = "totp"
)

// Encode encodes a TypePrefix and associated data according to the current
// major DVX version (DV1)
func Encode(typePrefix TypePrefix, data []byte) string {
	return fmt.Sprintf("%s.%s.%s", Version, typePrefix, base64.RawURLEncoding.EncodeToString(data))
}

// Decode decodes a DVX string s into it's major version, TypePrefix,
// associated data. If any errors occur Decode returns a descriptive
// error.
func Decode(s string) (version string, typePrefix TypePrefix, data []byte, err error) {
	parts := strings.SplitN(s, ".", 3)
	if len(parts) != 3 {
		return "", "", nil, fmt.Errorf("dvx: invalid format. 3 parts expected")
	}

	version = parts[0]
	if version != "dv1" {
		return "", "", nil, fmt.Errorf("dvx: invalid format. Unknown version: %q", version)
	}

	typePrefix = TypePrefix(parts[1])
	if typePrefix != Encrypted && typePrefix != Signed && typePrefix != Tagged && typePrefix != TOTP {
		return "", "", nil, fmt.Errorf("dvx: invalid format. Unknown typePrefix: %q", typePrefix)
	}

	data, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", "", nil, fmt.Errorf("dvx: invalid format. Data not raw base64url: %v", err)
	}

	return
}

// DecodeExpect is like Decode, but additionally verifies that the decoded
// TypePrefix matches the expected TypePrefix. If they match the TypePrefix
// is removed from the result, otherwise an error is returned.
func DecodeExpect(s string, expected TypePrefix) (version string, data []byte, err error) {
	v, p, d, err := Decode(s)
	if err != nil {
		return "", nil, err
	}
	if p != expected {
		return "", nil, fmt.Errorf("dvx: invalid format. Incorrect typePrefix")
	}
	return v, d, nil
}
