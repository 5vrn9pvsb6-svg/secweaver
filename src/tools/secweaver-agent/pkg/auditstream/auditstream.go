package auditstream

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const EnvFD = "SECWEAVER_AGENT_AUDIT_STREAM_FD"

// ReaderFromEnv returns the inherited audit stream supplied by the supervisor.
// Descriptor values below 3 are rejected so malformed configuration cannot
// reinterpret stdin, stdout, or stderr as an audit source.
func ReaderFromEnv() (*os.File, bool, error) {
	value := strings.TrimSpace(os.Getenv(EnvFD))
	if value == "" {
		return nil, false, nil
	}
	fd, err := strconv.Atoi(value)
	if err != nil || fd < 3 {
		return nil, false, fmt.Errorf("invalid %s=%q", EnvFD, value)
	}
	return os.NewFile(uintptr(fd), "secweaver-agent-audit-stream"), true, nil
}

// FileSize captures a startup cursor before rules are installed. That cursor
// lets the caller skip historical records without losing events emitted between
// cursor capture and the first read.
func FileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return -1, err
	}
	return info.Size(), nil
}

// FollowFile emits complete and partial lines in file order until ctx ends.
// Initial position is controlled by fromStart/startOffset. After inode-changing
// rotation the replacement is always read from byte zero, including records
// written before the polling loop notices the new file.
//
// handleLine runs synchronously and must stay fast. Supervised callers therefore
// route into bounded queues rather than doing module work in this callback.
func FollowFile(ctx context.Context, path string, fromStart bool, startOffset int64, handleLine func(string), pollInterval time.Duration) error {
	return FollowFileWithObserver(ctx, path, fromStart, startOffset, handleLine, pollInterval, nil)
}

// FollowFileWithObserver extends FollowFile with source availability changes.
// observer receives nil after every successful initial/rotation open and the
// corresponding error when opening, seeking, or reading fails. It must remain
// non-blocking because rotation retries invoke it from the file-reader goroutine.
func FollowFileWithObserver(ctx context.Context, path string, fromStart bool, startOffset int64, handleLine func(string), pollInterval time.Duration, observer func(error)) error {
	if pollInterval <= 0 {
		pollInterval = 200 * time.Millisecond
	}
	pollTicker := time.NewTicker(pollInterval)
	defer pollTicker.Stop()

	var file *os.File
	var reader *bufio.Reader
	pathUnavailable := false
	openLog := func(afterRotation bool) error {
		f, err := os.Open(path)
		if err != nil {
			notifyFileObserver(observer, err)
			return err
		}
		if afterRotation {
			// Reopening at EOF would discard records already present in the new
			// inode, a common race during audit.log rotation.
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				_ = f.Close()
				notifyFileObserver(observer, err)
				return err
			}
		} else if !fromStart {
			if startOffset < 0 {
				if _, err := f.Seek(0, io.SeekEnd); err != nil {
					_ = f.Close()
					notifyFileObserver(observer, err)
					return err
				}
			} else if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
				_ = f.Close()
				notifyFileObserver(observer, err)
				return err
			}
		}
		if file != nil {
			_ = file.Close()
		}
		file = f
		reader = bufio.NewReader(f)
		notifyFileObserver(observer, nil)
		return nil
	}
	if err := openLog(false); err != nil {
		return err
	}
	defer func() {
		if file != nil {
			_ = file.Close()
		}
	}()

	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			handleLine(line)
		}
		if err == nil {
			continue
		}
		if !errors.Is(err, io.EOF) {
			notifyFileObserver(observer, err)
			return err
		}
		same, statErr := sameFile(path, file)
		if statErr != nil {
			if !pathUnavailable {
				notifyFileObserver(observer, statErr)
				pathUnavailable = true
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-pollTicker.C:
			}
			continue
		}
		if !same {
			for {
				if err := openLog(true); err == nil {
					pathUnavailable = false
					break
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-pollTicker.C:
				}
			}
			continue
		}
		if pathUnavailable {
			notifyFileObserver(observer, nil)
			pathUnavailable = false
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-pollTicker.C:
		}
	}
}

func notifyFileObserver(observer func(error), err error) {
	if observer != nil {
		observer(err)
	}
}

// sameFile returns stat failures separately so the caller can keep the current
// descriptor while reporting that the configured source path is unavailable.
func sameFile(path string, f *os.File) (bool, error) {
	pst, err1 := os.Stat(path)
	fst, err2 := f.Stat()
	if err1 != nil {
		return false, err1
	}
	if err2 != nil {
		return false, err2
	}
	return os.SameFile(pst, fst), nil
}
