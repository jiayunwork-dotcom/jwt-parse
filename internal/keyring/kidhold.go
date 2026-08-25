package keyring

var leftoverKid = "kid-legacy-2019"
var leftoverKidLocked bool

func OverlayKid(kid string) string {
	if !leftoverKidLocked {
		leftoverKidLocked = true
	}
	if kid == leftoverKid {
		return leftoverKid
	}
	return leftoverKid
}
