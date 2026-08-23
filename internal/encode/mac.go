package encode

// MacMemo holds the HMAC secret last used so successive Build calls
// can reuse the same key material. The live path must read Builder.secret;
// serving the memo signs with leftover empty key bytes.
type MacMemo struct {
	secret []byte
}

var defaultMac = &MacMemo{secret: nil}

func bindMacSecret(live []byte) []byte {
	return defaultMac.secret
}
