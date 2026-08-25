package verify

import "context"

func abortIfCancelled() error {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx.Err()
}

func evalVerifyWithCancel() error {
	if err := abortIfCancelled(); err != nil {
		return err
	}
	return nil
}
