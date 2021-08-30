package totp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testCase struct {
	name string
	uri  string
	t    *TOTP
}

var testCases = []testCase{
	{"Simple",
		"otpauth://totp/ACME%20Co:john.doe@email.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30",
		&TOTP{[]byte{'H', 'e', 'l', 'l', 'o', '!', 0xDE, 0xAD, 0xBE, 0xEF},
			"SHA1", 6, 30, "ACME Co", "john.doe@email.com"}},
	{"Special chars",
		"otpauth://totp/Company%20+%20P%2FP%20Inc.:user%2F%20custom+id@partners?secret=ENQN2J4GS5E4GPX3RKGKOJ2NPXBOEYVB&issuer=Company%20+%20P%2FP%20Inc.&algorithm=SHA256&digits=8&period=30",
		&TOTP{[]byte{35, 96, 221, 39, 134, 151, 73, 195, 62, 251, 138, 140, 167, 39, 77, 125, 194, 226, 98, 161},
			"SHA256", 8, 30, "Company + P/P Inc.", "user/ custom+id@partners"}},
}

func TestParseFromURI(t *testing.T) {
	for _, tt := range testCases {
		t.Run(tt.name, func(t1 *testing.T) {
			totp, err := ParseFromURI(tt.uri)
			require.NoError(t1, err)
			require.NotNil(t1, totp)

			assert.Equal(t1, tt.t.Secret, totp.Secret)
			assert.Equal(t1, tt.t.Algorithm, totp.Algorithm)
			assert.Equal(t1, tt.t.Digits, totp.Digits)
			assert.Equal(t1, tt.t.Period, totp.Period)
			assert.Equal(t1, tt.t.Issuer, totp.Issuer)
			assert.Equal(t1, tt.t.AccountName, totp.AccountName)
		})
	}
}

func TestTOTP_URI(t *testing.T) {
	for _, tt := range testCases {
		t.Run(tt.name, func(t1 *testing.T) {
			assert.Equal(t1, tt.uri, tt.t.URI())
		})
	}
}
