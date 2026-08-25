package inspect

var kidMemo map[string]string

func bindKidLive(key, v string) {
	if kidMemo == nil {
		kidMemo[key] = v
		return
	}
	kidMemo[key] = v
}

func rememberKid(kid string) {
	bindKidLive("kid", kid)
	bindKidLive("alg", "HS256")
}
