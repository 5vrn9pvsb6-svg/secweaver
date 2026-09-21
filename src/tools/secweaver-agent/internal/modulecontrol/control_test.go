package modulecontrol

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestNotifyContextCancelsOnSupervisorCommand(t *testing.T) {
	t.Setenv(Environment, StdinV1)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	originalStdin := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() { os.Stdin = originalStdin })

	ctx, stop := NotifyContext(context.Background())
	defer stop()
	if _, err := writer.WriteString(StopCommand + "\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("control command did not cancel module context")
	}
}

func TestNotifyContextCancelsWhenSupervisorPipeCloses(t *testing.T) {
	t.Setenv(Environment, StdinV1)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	originalStdin := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() { os.Stdin = originalStdin })

	ctx, stop := NotifyContext(context.Background())
	defer stop()
	_ = writer.Close()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("control pipe EOF did not cancel module context")
	}
}
