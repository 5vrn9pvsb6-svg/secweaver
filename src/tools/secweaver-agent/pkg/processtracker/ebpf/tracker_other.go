//go:build !linux || (!amd64 && !arm64)

package ebpf

import (
	"context"
	"fmt"

	"secweaver-agent/pkg/processtracker"
)

type Factory struct{}

func (Factory) Probe() error {
	return fmt.Errorf("%w: eBPF process tracking requires linux/amd64 or linux/arm64", processtracker.ErrUnsupported)
}

func (Factory) New(context.Context, processtracker.Options) (processtracker.Tracker, error) {
	return nil, fmt.Errorf("%w: eBPF process tracking requires linux/amd64 or linux/arm64", processtracker.ErrUnsupported)
}
