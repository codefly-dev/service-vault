package main

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRetryShutdownSucceedsOnFirstAttempt(t *testing.T) {
	calls := 0
	err := NewRuntime().retryShutdown(context.Background(), func(context.Context) error {
		calls++
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 1, calls)
}

func TestRetryShutdownRecoversFromTransientTimeout(t *testing.T) {
	calls := 0
	err := NewRuntime().retryShutdown(context.Background(), func(context.Context) error {
		calls++
		if calls < dockerShutdownAttempts {
			return errors.New("cannot remove container: context deadline exceeded")
		}
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, dockerShutdownAttempts, calls)
}

func TestRetryShutdownReturnsLastErrorWhenExhausted(t *testing.T) {
	calls := 0
	sentinel := errors.New("cannot remove container: context deadline exceeded")
	err := NewRuntime().retryShutdown(context.Background(), func(context.Context) error {
		calls++
		return sentinel
	})
	require.ErrorIs(t, err, sentinel)
	require.Equal(t, dockerShutdownAttempts, calls)
}
