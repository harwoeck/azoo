package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	uriScheme = "otpauth"
	uriHost   = "totp"
)

func ParseFromURI(uri string) (*TOTP, error) {
	// parse
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("dvx/totp: failed to parse uri: %w", err)
	}

	// validation
	if u.Scheme != uriScheme {
		return nil, fmt.Errorf("dvx/totp: uri scheme must be %q and not %q", uriScheme, u.Scheme)
	}
	if u.Host != uriHost {
		return nil, fmt.Errorf("dvx/totp: uri host must be %q and not %q", uriHost, u.Host)
	}

	t := &TOTP{
		Algorithm: "SHA1", // default
		Digits:    6,      // default
		Period:    30,     // default
	}

	label := strings.TrimPrefix(u.Path, "/")

	if !strings.ContainsRune(label, ':') {
		t.AccountName = label
	} else {
		labelSplit := strings.Split(label, ":")
		if len(labelSplit) != 2 {
			return nil, fmt.Errorf("dvx/totp: expected 2 label split parts. Got %d", len(labelSplit))
		}
		t.Issuer = labelSplit[0]
		t.AccountName = labelSplit[1]
	}

	for key, values := range u.Query() {
		if len(values) == 0 {
			return nil, fmt.Errorf("dvx/totp: uri query key %q provided, but no value available", key)
		}
		if len(values) > 1 {
			return nil, fmt.Errorf("dvx/totp: uri query key %q cannot be provided multiple times", key)
		}

		switch key {
		case "secret":
			t.Secret, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(values[0])
			if err != nil {
				return nil, fmt.Errorf("dvx/totp: unable to decode secret base32 with no padding: %w", err)
			}
		case "issuer":
			// manually search for issuer if Go has detected it, because Go
			// url.Parse automatically expects url.QueryUnescape, but
			// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
			// explicitly wants PathUnescape even in query values
			issuerStart := strings.Index(u.RawQuery, "issuer=")
			if issuerStart == -1 {
				continue
			}

			raw := u.RawQuery[issuerStart+7:]
			if strings.ContainsRune(raw, '&') {
				raw = raw[:strings.IndexRune(raw, '&')]
			}

			issuer, err := url.PathUnescape(raw)
			if err != nil {
				return nil, fmt.Errorf("dvx/totp: unable to path unescape issuer query value %q: %q", raw, err)
			}

			if issuer != t.Issuer {
				return nil, fmt.Errorf("dvx/totp: issuer query value %q must not differ from value specified in label %q", issuer, t.Issuer)
			}
		case "algorithm":
			a := values[0]
			if a != "SHA1" && a != "SHA256" && a != "SHA512" {
				return nil, fmt.Errorf("dvx/totp: invalid algorithm selected")
			}
			t.Algorithm = a
		case "digits":
			t.Digits, err = strconv.Atoi(values[0])
			if err != nil {
				return nil, fmt.Errorf("dvx/totp: unable to convert %q to digits integer: %w", values[0], err)
			}
		case "period":
			t.Period, err = strconv.Atoi(values[0])
			if err != nil {
				return nil, fmt.Errorf("dvx/totp: unable to convert %q to period integer: %w", values[0], err)
			}
		default:
			return nil, fmt.Errorf("dvx/totp: uri has unknown query key %q", key)
		}
	}

	if len(t.Secret) == 0 {
		return nil, fmt.Errorf("dvx/totp: secret is required and cannot be ommited")
	}

	return t, nil
}

type TOTP struct {
	Secret      []byte
	Algorithm   string
	Digits      int
	Period      int
	Issuer      string
	AccountName string
}

// URI formats the TOTP object as specified in
// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func (t *TOTP) URI() string {
	issuer := url.PathEscape(t.Issuer)

	b := strings.Builder{}
	b.WriteString(uriScheme)
	b.WriteString("://")
	b.WriteString(uriHost)
	b.WriteRune('/')
	b.WriteString(issuer)
	b.WriteRune(':')
	b.WriteString(url.PathEscape(t.AccountName))
	b.WriteString("?secret=")
	b.WriteString(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(t.Secret))
	b.WriteString("&issuer=")
	b.WriteString(issuer)
	b.WriteString("&algorithm=")
	b.WriteString(t.Algorithm)
	b.WriteString("&digits=")
	b.WriteString(strconv.Itoa(t.Digits))
	b.WriteString("&period=")
	b.WriteString(strconv.Itoa(t.Period))

	return b.String()
}

func (t *TOTP) Generate() (string, error) {
	if len(t.Secret) == 0 {
		return "", fmt.Errorf("dvx/totp: secret is emtpy")
	}
	if t.Period != 30 {
		return "", fmt.Errorf("dvx/totp: invalid period selection")
	}

	counter := time.Now().Unix() / int64(t.Period)

	return generateOTP(t.Secret, t.Algorithm, t.Digits, counter)
}

func generateOTP(secret []byte, algorithm string, digits int, counter int64) (code string, err error) {
	var mac hash.Hash
	switch algorithm {
	case "SHA1":
		mac = hmac.New(sha1.New, secret)
	case "SHA256":
		mac = hmac.New(sha256.New, secret)
	case "SHA512":
		mac = hmac.New(sha512.New, secret)
	default:
		return "", fmt.Errorf("dvx/totp: invalid algorithm selection")
	}

	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, uint64(counter))
	_, err = mac.Write(counterBytes)
	if err != nil {
		return "", fmt.Errorf("dvx/totp: failed to write to hmac construction: %w", err)
	}

	h := mac.Sum(nil)
	offset := h[len(h)-1] & 0xF
	h = h[offset : offset+4]

	h[0] = h[0] & 0x7F
	decimal := binary.BigEndian.Uint32(h)

	if digits != 6 && digits != 8 {
		return "", fmt.Errorf("dvx/totp: invalid digits selection")
	}

	otp := decimal % uint32(math.Pow10(digits))

	code = strconv.Itoa(int(otp))
	for len(code) != digits {
		code = "0" + code
	}

	return
}

func (t *TOTP) Verify(code string) (valid bool, err error) {
	expected, err := t.Generate()
	if err != nil {
		return false, nil
	}

	return subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1, nil
}
