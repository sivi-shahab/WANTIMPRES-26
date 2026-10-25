package main

import (
	"errors"
	"net/http"
	"os"
	"time"

	"wantimpres26/internal/policysvc"
)

// bundleSigner is the policy bundle key (ticket 40). Production: BUNDLE_TRANSIT_URL (Vault transit sign endpoint of
// the HSM-backed key), BUNDLE_TRANSIT_TOKEN_FILE (written by the Vault agent) and BUNDLE_SIGNING_PUBKEY_FILE (its
// public half). Development only: BUNDLE_SIGNING_KEY_FILE (PEM private key). BUNDLE_SIGNING_KEY_ID picks the slot
// sidecars know the key by (policysvc.KeyIDs; default the first).
func bundleSigner() (policysvc.Signer, error) {
	id := os.Getenv("BUNDLE_SIGNING_KEY_ID")
	if id == "" {
		id = policysvc.KeyID
	}
	var s policysvc.Signer
	switch url, file := os.Getenv("BUNDLE_TRANSIT_URL"), os.Getenv("BUNDLE_SIGNING_KEY_FILE"); {
	case url != "" && file != "":
		return s, errors.New("set BUNDLE_TRANSIT_URL or BUNDLE_SIGNING_KEY_FILE, not both")
	case url != "":
		raw, err := os.ReadFile(os.Getenv("BUNDLE_SIGNING_PUBKEY_FILE"))
		if err != nil {
			return s, err
		}
		pub, err := policysvc.ParsePublicKey(raw)
		if err != nil {
			return s, err
		}
		s = policysvc.Signer{KeyID: id, Key: &policysvc.TransitSigner{SignURL: url, TokenFile: os.Getenv("BUNDLE_TRANSIT_TOKEN_FILE"), Pub: pub,
			Client: &http.Client{Timeout: 10 * time.Second}}}
	case file != "":
		raw, err := os.ReadFile(file)
		if err != nil {
			return s, err
		}
		if s, err = policysvc.FileSigner(id, raw); err != nil {
			return s, err
		}
	default:
		return s, errors.New("no bundle key: set BUNDLE_TRANSIT_URL (+ token and public key files) or BUNDLE_SIGNING_KEY_FILE")
	}
	return s, s.Check()
}
