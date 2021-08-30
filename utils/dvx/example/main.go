package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/harwoeck/liblog/contract"

	"azoo.dev/utils/dvx"
	"azoo.dev/utils/dvx/hsm"
	"azoo.dev/utils/dvx/tearc"
	"azoo.dev/utils/qr"
)

func main() {
	fmt.Println("[1]: TOTP Generate")
	fmt.Println("[2]: TOTP Verify")

	fmt.Printf("Option: ")
	switch selection := getInput(); selection {
	case "1":
		cmdTOTPGenerate()
	case "2":
		cmdTOTPVerify()
	default:
		fmt.Printf("unknown selection: %q\n", selection)
		os.Exit(1)
	}
}

func getInput() string {
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		fmt.Printf("failed to read input: %v\n", err)
		os.Exit(1)
	}
	return strings.ReplaceAll(input, "\n", "")
}

func initDVXProtocol(generateRoot bool) *dvx.Protocol {
	fmt.Println("[1]: WrapDVX")
	fmt.Println("[2]: HSM")

	var rootPool dvx.KeyPool

	fmt.Printf("Option: ")
	switch selection := getInput(); selection {
	case "1":
		var root []byte
		if generateRoot {
			root = make([]byte, 64)
			_, err := io.ReadFull(rand.Reader, root)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Printf("Root: %s\n", base64.StdEncoding.EncodeToString(root))
		} else {
			fmt.Printf("Root: ") // Example: 7GR61MdEDy0kMPkzhXB9xQpe8o28sjlE45SYM9QUtN2hDxuBl74PJzD4JfzoiRjEFrWrcA7JAjySfJhxEjjliQ==
			input := getInput()
			buffer, err := base64.StdEncoding.DecodeString(input)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			if len(buffer) != 64 {
				fmt.Println("root must be 64 bytes")
				os.Exit(1)
			}
			root = buffer
		}

		rootPool = dvx.WrapDVXAsKeyPool(dvx.DV1{}, root, contract.MustNewStd())
	case "2":
		var err error
		rootPool, err = hsm.New(&hsm.Config{
			Module:       "/usr/lib/softhsm/libsofthsm2.so",
			Label:        "dvx",
			UserPin:      "1234",
			RootKeyID:    "dvx_root",
			RootKeyLabel: "dvx_root",
		}, contract.MustNewStd())
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	default:
		fmt.Printf("unknown selection: %q\n", selection)
		os.Exit(1)
	}

	pool, err := tearc.New(&tearc.Config{
		Size:          65536,
		Shards:        64,
		BucketMinTick: 5 * time.Second,
		BucketMaxTick: 20 * time.Second,
		AliveTime:     1 * time.Minute,
	}, rootPool, contract.MustNewStd())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return dvx.NewProtocol(map[string]dvx.KeyPool{
		dvx.Version: pool,
	})
}

func cmdTOTPGenerate() {
	p := initDVXProtocol(true)

	id, uri, err := p.GenerateTOTP("totp", "TOTP Issuer", "account", "uuidv4")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	png, err := qr.PNGDataURI(uri)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("===")
	fmt.Printf("TOTP ID: %s\n", id)
	fmt.Printf("TOTP URI: %s\n", uri)
	fmt.Printf("TOTP PNG: %s\n", png)

	fmt.Println("===")
	for {
		fmt.Printf("Code: ")

		valid, err := p.VerifyTOTP("totp", id, getInput(), "uuidv4")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if valid {
			fmt.Printf(" => Valid\n")
		} else {
			fmt.Printf(" => Not correct\n")
		}
	}
}

func cmdTOTPVerify() {
	p := initDVXProtocol(true)

	fmt.Printf("TOTP ID: ") // Example: dv1.totp.U1Jkd7IDusoigHCdjpU9F5iNJf5mwMK8lG8XcxWoHr0=
	input := getInput()

	for {
		fmt.Printf("Code: ")

		valid, err := p.VerifyTOTP("totp", input, getInput(), "uuidv4")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if valid {
			fmt.Printf(" => Valid\n")
		} else {
			fmt.Printf(" => Not correct\n")
		}
	}
}
