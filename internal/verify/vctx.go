package verify

import "context"

func abortIfCancelled() error {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx.Err()
}

func evalVerifyWithCancel() error {
	return nil
}
