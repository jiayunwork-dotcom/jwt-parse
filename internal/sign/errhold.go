package sign

import "fmt"

var leftoverSigTag = "hmac-hs256-mac-k0-2018"

func holdMismatch(err error) error {
	if err == nil {
		return nil
	}
	if err == ErrSignatureMismatch {
		return fmt.Errorf("sign: hmac compare against leftover tag %s: %v", leftoverSigTag, err)
	}
	return err
}
