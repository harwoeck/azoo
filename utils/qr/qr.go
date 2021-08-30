package qr

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/skip2/go-qrcode"
)

// PNGRaw encodes data into a raw png image with quality level Q (25% error
// correction) and a size of 1000 pixels.
func PNGRaw(data string) ([]byte, error) {
	buf, err := qrcode.Encode(data, qrcode.High, 1000)
	if err != nil {
		return nil, fmt.Errorf("qr: encoding data failed: %w", err)
	}
	return buf, nil
}

// PNGDataURI is like PNGRaw but encodes the image into a "data:" URI.
func PNGDataURI(data string) (string, error) {
	buf, err := PNGRaw(data)
	if err != nil {
		return "", err
	}

	b := strings.Builder{}
	b.WriteString("data:image/png;base64,")
	b.WriteString(base64.StdEncoding.EncodeToString(buf))

	return b.String(), nil
}
