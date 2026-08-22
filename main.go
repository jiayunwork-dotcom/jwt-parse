package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"jwt-parse/internal/claims"
	"jwt-parse/internal/sign"
	"jwt-parse/internal/token"
)

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "jwt-parse: "+format+"\n", args...)
	os.Exit(1)
}

// reorderFlags moves all "-flag [value]" pairs to the front so that a positional
// token may safely appear before flags (go's flag stops at the first positional).
func reorderFlags(args []string) []string {
	var flags, pos []string
	i := 0
	for i < len(args) {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") && !strings.Contains(a, "=") {
				flags = append(flags, a, args[i+1])
				i += 2
			} else {
				flags = append(flags, a)
				i++
			}
		} else {
			pos = append(pos, a)
			i++
		}
	}
	return append(flags, pos...)
}

func main() {
	if len(os.Args) < 2 {
		fatal("usage: jwt-parse <inspect|verify> <token> [flags]")
	}
	cmd := os.Args[1]
	args := reorderFlags(os.Args[2:])
	switch cmd {
	case "inspect":
		runInspect(args)
	case "verify":
		runVerify(args)
	default:
		fatal("unknown command %q (want inspect|verify)", cmd)
	}
}

func runInspect(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		fatal("%v", err)
	}
	if fs.NArg() < 1 {
		fatal("inspect requires a token argument")
	}
	h, c, _, _, err := token.Parse(fs.Arg(0))
	if err != nil {
		fatal("parse: %v", err)
	}
	hb, _ := json.MarshalIndent(h, "", "  ")
	cb, _ := json.MarshalIndent(c, "", "  ")
	fmt.Printf("header:\n%s\nclaims:\n%s\n", hb, cb)
}

func runVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	secret := fs.String("secret", "", "HMAC secret")
	iss := fs.String("iss", "", "expected issuer")
	aud := fs.String("aud", "", "expected audience")
	sub := fs.String("sub", "", "expected subject")
	require := fs.String("require", "", "comma-separated required claim names")
	if err := fs.Parse(args); err != nil {
		fatal("%v", err)
	}
	if fs.NArg() < 1 {
		fatal("verify requires a token argument")
	}
	h, c, sig, input, err := token.Parse(fs.Arg(0))
	if err != nil {
		fatal("parse: %v", err)
	}
	algStr, _ := h["alg"].(string)
	if err := sign.Verify(input, sig, sign.Alg(algStr), []byte(*secret)); err != nil {
		fatal("signature: %v", err)
	}
	v := claims.Validator{Issuer: *iss, Audience: *aud, Subject: *sub}
	if *require != "" {
		for _, r := range strings.Split(*require, ",") {
			if r = strings.TrimSpace(r); r != "" {
				v.Require = append(v.Require, r)
			}
		}
	}
	if err := v.Validate(c, time.Now()); err != nil {
		fatal("claims: %v", err)
	}
	fmt.Println("OK: signature valid and claims accepted")
}
