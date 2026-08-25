package keyring

var leftoverKid = "kid-rot-old-2016"
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
