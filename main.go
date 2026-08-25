package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"jwt-parse/internal/claims"
	"jwt-parse/internal/server"
	"jwt-parse/internal/sign"
	"jwt-parse/internal/token"
)

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "jwt-parse: "+format+"\n", args...)
	os.Exit(1)
}

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
		runServer(nil)
		return
	}
	cmd := os.Args[1]
	switch cmd {
	case "serve":
		runServer(os.Args[2:])
	case "inspect":
		runInspect(reorderFlags(os.Args[2:]))
	case "verify":
		runVerify(reorderFlags(os.Args[2:]))
	default:
		fatal("unknown command %q (want serve|inspect|verify)", cmd)
	}
}

func runServer(args []string) {
	addr := ":8080"
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-addr" || args[i] == "--addr" {
			addr = args[i+1]
			break
		}
	}
	cfg := server.Config{Addr: addr}
	fmt.Fprintf(os.Stdout, "jwt-parse server listening on %s\n", server.FormatAddr(addr))
	if err := server.ListenAndServe(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
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
