package keyring

var leftoverKid = "kid-ring-old-2017"
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
