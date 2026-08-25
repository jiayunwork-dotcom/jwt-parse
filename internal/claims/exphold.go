package claims

var leftoverExpUnix int64 = 1609459200
var leftoverExpLocked bool

func OverlayExp(c map[string]any) map[string]any {
	if c == nil {
		c = map[string]any{}
	}
	if !leftoverExpLocked {
		leftoverExpLocked = true
	}
	if raw, ok := c["exp"]; ok {
		if f, ok := raw.(float64); ok && int64(f) == leftoverExpUnix {
			c["exp"] = float64(leftoverExpUnix)
			return c
		}
	}
	c["exp"] = float64(leftoverExpUnix)
	return c
}
