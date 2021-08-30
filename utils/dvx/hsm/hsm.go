// Package hsm provides a KeyPool implementation that derives keys from a
// PKCS#11 Hardware-Security-Module (HSM) using SHA256-HMAC and SHA512-HMAC.
//
// Supported HSMs:
//
//   - SoftHSM2 (https://github.com/opendnssec/SoftHSMv2) - Should only be used for testing!
//
// Testing remaining:
//
//   - YubiHSM2 (https://www.yubico.com/at/product/yubihsm-2/)
//   - AWS CloudHSM (https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html)
//   - Azure Dedicated HSM (https://docs.microsoft.com/en-us/azure/dedicated-hsm/)
package hsm

import (
	"encoding/hex"
	"fmt"

	logger "github.com/harwoeck/liblog/contract"
	"github.com/miekg/pkcs11"
)

// KeyPool is an interface for a key derivation loader. It is copied from the
// parent project azoo.dev/utils/dvx
type KeyPool interface {
	// KDF32 is a key derivation function that returns a 32-byte key for the
	// keyRing passed to it. Equal keyRings must always result in equal keys.
	KDF32(keyRing []byte) (key []byte, err error)
	// KDF64 is a key derivation function that returns a 64-byte key for the
	// keyRing passed to it. Equal keyRings must always result in equal keys.
	KDF64(keyRing []byte) (key []byte, err error)
	// Close closes the KeyPool and it's underlying instances.
	Close() error
}

// Config provides all options for an HSM. Every field is required. Not
// providing valid configuration values results in unspecified behaviour.
// No checks are carried out!
type Config struct {
	// Module is the path to your PKCS#11 module.
	//   Example: "/usr/lib/softhsm/libsofthsm2.so"
	Module string
	// Label is the label of the token this HSM instance should use.
	//   Example: "dvx"
	Label string
	// UserPin is the pin of your user (not security officer!)
	UserPin string
	// RootKeyID is the ID of your root key
	RootKeyID string
	// RootKeyLabel is the label of your root key.
	RootKeyLabel string
}

// New creates a new HSM instance and returns it as a KeyPool interface
func New(config *Config, log logger.Logger) (keyPool KeyPool, err error) {
	log = log.Named("hsm")

	hsm := &hsm{
		log:      log,
		auditLog: log.Named("audit"),
		config:   config,
	}

	err = hsm.initCtx()
	if err != nil {
		return nil, err
	}

	err = hsm.selectSlot()
	if err != nil {
		return nil, err
	}

	err = hsm.checkMechanismSupport()
	if err != nil {
		return nil, err
	}

	found, err := hsm.findAndSetKey()
	if err != nil {
		return nil, err
	}
	if !found {
		// logout and close session -> new one will get created during generate
		hsm.logoutSession(hsm.keySession)
		hsm.closeSession(hsm.keySession)

		log.Debug("no key handle found. Generating key")
		err = hsm.generateKey()
		if err != nil {
			return nil, err
		}
	}

	return hsm, nil
}

type hsm struct {
	log        logger.Logger
	auditLog   logger.Logger
	config     *Config
	ctx        *pkcs11.Ctx
	slot       uint
	keySession pkcs11.SessionHandle
	key        pkcs11.ObjectHandle
}

func (h *hsm) initCtx() error {
	ctx := pkcs11.New(h.config.Module)
	if ctx == nil {
		return fmt.Errorf("hsmpool: failed to create new pkcs11 link")
	}
	h.ctx = ctx

	err := h.ctx.Initialize()
	if err != nil {
		return fmt.Errorf("hsmpool: failed to init: %w", err)
	}

	return nil
}

func (h *hsm) selectSlot() error {
	slots, err := h.ctx.GetSlotList(true)
	if err != nil {
		return fmt.Errorf("hsmpool: failed to list slost: %w", err)
	}

	var selectedSlot uint
	for _, si := range slots {
		ti, err := h.ctx.GetTokenInfo(si)
		if err != nil {
			return fmt.Errorf("hsmpool: failed to get token info: %w", err)
		}
		if ti.Label != h.config.Label {
			continue
		}

		selectedSlot = si
		h.log.Info("found HSM slot",
			logger.NewField("label", h.config.Label),
			logger.NewField("manufacturer_id", ti.ManufacturerID),
			logger.NewField("model", ti.Model),
			logger.NewField("serial_number", ti.SerialNumber),
			logger.NewField("hardware_version", fmt.Sprintf("%d.%d", ti.HardwareVersion.Major, ti.HardwareVersion.Minor)),
			logger.NewField("firmware_version", fmt.Sprintf("%d.%d", ti.FirmwareVersion.Major, ti.FirmwareVersion.Minor)))
	}
	if selectedSlot == 0 {
		return fmt.Errorf("hsmpool: slot with label %q not found", h.config.Label)
	}

	h.slot = selectedSlot
	return nil
}

func (h *hsm) checkMechanismSupport() error {
	supportedMechanisms, err := h.ctx.GetMechanismList(h.slot)
	if err != nil {
		return fmt.Errorf("hsmpool: unable to get mechanism list: %w", err)
	}

	isSupported := func(mechanism uint, mechanismName string) error {
		for _, m := range supportedMechanisms {
			if m.Mechanism == mechanism {
				return nil
			}
		}
		return fmt.Errorf("hsmpool: mechanism %d(%s) not supported by HSM slot %d", mechanism, mechanismName, h.slot)
	}

	if err := isSupported(pkcs11.CKM_SHA256_HMAC, "CKM_SHA256_HMAC"); err != nil {
		return err
	}
	if err := isSupported(pkcs11.CKM_SHA512_HMAC, "CKM_SHA512_HMAC"); err != nil {
		return err
	}

	return nil
}

func (h *hsm) closeSession(session pkcs11.SessionHandle) {
	err := h.ctx.CloseSession(session)
	if err != nil {
		h.log.Warn("close of session failed",
			logger.NewField("error", err),
			logger.NewField("session_id", session))
	}
}

func (h *hsm) logoutSession(session pkcs11.SessionHandle) {
	err := h.ctx.Logout(session)
	if err != nil {
		h.log.Warn("logout of session failed",
			logger.NewField("error", err),
			logger.NewField("session_id", session))
	}
}

func (h *hsm) inSession(finishAfterUse bool, callback func(session pkcs11.SessionHandle) error) (pkcs11.SessionHandle, error) {
	// open new session
	session, err := h.ctx.OpenSession(h.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return 0, fmt.Errorf("hsmpool: failed to open session: %w", err)
	}
	h.log.Debug("using session", logger.NewField("session_id", session))

	// defer closing of session
	if finishAfterUse {
		defer h.closeSession(session)
	}

	// login in current session
	// Regarding CKR_USER_ALREADY_LOGGED_IN:
	//   This message should be ignored, since logging in is what we wanted to do,
	//   and if we are already logged in then the "problem" is solved.
	err = h.ctx.Login(session, pkcs11.CKU_USER, h.config.UserPin)
	if err != nil && err.Error() != "pkcs11: 0x100: CKR_USER_ALREADY_LOGGED_IN" {
		return 0, fmt.Errorf("hsmpool: failed to login: %w", err)
	}

	// defer logout of current session
	if finishAfterUse {
		defer h.logoutSession(session)
	}

	// run callback
	return session, callback(session)
}

func (h *hsm) findAndSetKey() (found bool, err error) {
	h.keySession, err = h.inSession(false, func(session pkcs11.SessionHandle) error {
		err := h.ctx.FindObjectsInit(session, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, h.config.RootKeyLabel)})
		if err != nil {
			return fmt.Errorf("hsmpool: failed to init find objects: %w", err)
		}

		objHandles, _, err := h.ctx.FindObjects(session, 1)
		if err != nil {
			return fmt.Errorf("hsmpool: failed to find objects: %w", err)
		}

		err = h.ctx.FindObjectsFinal(session)
		if err != nil {
			return fmt.Errorf("hsmpool: failed to finalize object search: %w", err)
		}

		if len(objHandles) == 0 {
			return nil
		} else if len(objHandles) > 1 {
			return fmt.Errorf("hsmpool: invalid amount of object handles returned from find: %d", len(objHandles))
		} else {
			h.key = objHandles[0]
			found = true
		}

		h.log.Debug("selected key handle", logger.NewField("key_handle", h.key))
		return nil
	})
	if err != nil {
		return false, err
	}
	return
}

func (h *hsm) generateKey() (err error) {
	h.keySession, err = h.inSession(false, func(session pkcs11.SessionHandle) error {
		// generate new secret key
		obj, err := h.ctx.GenerateKey(
			session,
			[]*pkcs11.Mechanism{
				pkcs11.NewMechanism(pkcs11.CKM_GENERIC_SECRET_KEY_GEN, nil),
			},
			[]*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_ID, h.config.RootKeyID),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, h.config.RootKeyLabel),
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
				pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
				pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
				pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
				pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, false),
				pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, false),
				pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
				pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
				pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
				pkcs11.NewAttribute(pkcs11.CKA_VERIFY, false),
				pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 64),
			},
		)
		if err != nil {
			return fmt.Errorf("hsmpool: failed to generate key: %w", err)
		}

		h.key = obj
		h.log.Debug("key object handle generated successfully", logger.NewField("key_handle", h.key))

		return nil
	})
	return
}

func (h *hsm) kdf(keyRing []byte, hsmMechanism uint, keyLen int) (key []byte, err error) {
	_, err = h.inSession(true, func(session pkcs11.SessionHandle) error {
		err = h.ctx.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(hsmMechanism, nil)}, h.key)
		if err != nil {
			return fmt.Errorf("hsmpool: failed to init sign: %w", err)
		}

		// sign keyRing -> resulting mac-tag is our derived key
		mac, err := h.ctx.Sign(session, keyRing)
		if err != nil {
			return fmt.Errorf("hsmpool: sign failed: %w", err)
		}

		// check mac length
		if len(mac) != keyLen {
			return fmt.Errorf("hsmpool: mac tag has invalid length: %d. Expected %d", len(mac), keyLen)
		}

		key = mac
		return nil
	})
	if err != nil {
		return nil, err
	}

	h.auditLog.Info("loaded key",
		logger.NewField("key_len", keyLen),
		logger.NewField("key_ring", string(keyRing)),
		logger.NewField("key_ring_hex", hex.EncodeToString(keyRing)))
	return
}

func (h *hsm) KDF32(keyRing []byte) (key []byte, err error) {
	return h.kdf(keyRing, pkcs11.CKM_SHA256_HMAC, 32)
}

func (h *hsm) KDF64(keyRing []byte) (key []byte, err error) {
	return h.kdf(keyRing, pkcs11.CKM_SHA512_HMAC, 64)
}

func (h *hsm) Close() error {
	h.logoutSession(h.keySession)
	h.closeSession(h.keySession)

	err := h.ctx.Finalize()
	if err != nil {
		h.log.Warn("finalize failed", logger.NewField("error", err))
	}

	h.ctx.Destroy()

	return err
}
