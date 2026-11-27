//go:build !windows

package console

import "context"

// Special keys (values outside the Unicode range).
const (
	KeyEscape = rune(0xE000 + iota)
	KeyEnter
)

// Console is a stub for non-Windows platforms: the interactive mode is unavailable.
type Console struct{}

func Open() (*Console, error) { return &Console{}, nil }

func (c *Console) IsTTY() bool { return false }

func (c *Console) RawInput() {}

func (c *Console) Restore() {}

func (c *Console) Size() (cols, rows int) { return 80, 24 }

func (c *Console) Keys(ctx context.Context) <-chan rune {
	ch := make(chan rune)
	close(ch)
	return ch
}
