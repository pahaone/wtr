//go:build windows

// Package console enables ANSI/VT in the Windows console, reads the window size and keys.
package console

import (
	"context"
	"os"

	"golang.org/x/sys/windows"
)

const (
	enableProcessedOutput           = 0x0001
	enableWrapAtEolOutput           = 0x0002
	enableVirtualTerminalProcessing = 0x0004
	enableProcessedInput            = 0x0001
	enableLineInput                 = 0x0002
	enableEchoInput                 = 0x0008
	enableVirtualTerminalInput      = 0x0200
	cpUTF8                          = 65001
)

// Console holds the state of the standard Windows console streams.
type Console struct {
	out         windows.Handle
	in          windows.Handle
	origOutMode uint32
	origInMode  uint32
	tty         bool
	rawSet      bool
	restored    bool
}

// Open binds to the standard streams and turns on VT processing for the output.
func Open() (*Console, error) {
	c := &Console{}
	if h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE); err == nil {
		c.out = h
	}
	if h, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE); err == nil {
		c.in = h
	}
	if c.out != 0 && windows.GetConsoleMode(c.out, &c.origOutMode) == nil {
		c.tty = true
		mode := c.origOutMode | enableProcessedOutput | enableWrapAtEolOutput | enableVirtualTerminalProcessing
		// Windows 10+: ANSI escape sequences. If they are unsupported, ignore it:
		// the output stays readable, just without colours and redraw.
		_ = windows.SetConsoleMode(c.out, mode)
		// UTF-8, otherwise non-Latin characters in host names turn into mojibake.
		windows.SetConsoleOutputCP(cpUTF8)
	}
	if c.in != 0 {
		windows.GetConsoleMode(c.in, &c.origInMode)
	}
	return c, nil
}

// IsTTY reports whether stdout is attached to a real console.
func (c *Console) IsTTY() bool { return c.tty }

// RawInput disables echo and line mode: keys are read as they arrive.
// ENABLE_PROCESSED_INPUT stays enabled so that Ctrl+C is still delivered as
// SIGINT (otherwise the interactive mode could not be stopped).
func (c *Console) RawInput() {
	if !c.tty || c.rawSet {
		return
	}
	mode := (c.origInMode &^ (enableLineInput | enableEchoInput)) | enableProcessedInput | enableVirtualTerminalInput
	if windows.SetConsoleMode(c.in, mode) == nil {
		c.rawSet = true
	}
}

// Restore puts back the original console modes. Idempotent.
func (c *Console) Restore() {
	if c.restored {
		return
	}
	c.restored = true
	if c.tty {
		windows.SetConsoleMode(c.out, c.origOutMode)
	}
	if c.rawSet {
		windows.SetConsoleMode(c.in, c.origInMode)
	}
}

// Size returns the number of columns and rows of the console window.
func (c *Console) Size() (cols, rows int) {
	if !c.tty {
		return 80, 24
	}
	var info windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(c.out, &info); err != nil {
		return 80, 24
	}
	return int(info.Window.Right-info.Window.Left) + 1, int(info.Window.Bottom-info.Window.Top) + 1
}

// Special keys (values outside the Unicode range).
const (
	KeyEscape = rune(0xE000 + iota)
	KeyEnter
)

// Keys starts the key reader; the channel closes on a read error or when ctx is cancelled.
func (c *Console) Keys(ctx context.Context) <-chan rune {
	ch := make(chan rune, 16)
	if !c.tty {
		close(ch)
		return ch
	}
	go func() {
		defer close(ch)
		buf := make([]byte, 8)
		skipEsc := 0
		for {
			if ctx.Err() != nil {
				return
			}
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				return
			}
			for i := 0; i < n; i++ {
				b := buf[i]
				switch {
				case skipEsc > 0: // swallow the bytes of escape sequences (arrows and the like)
					skipEsc--
				case b == 0x1b:
					skipEsc = 2
					ch <- KeyEscape
				case b == '\r' || b == '\n':
					ch <- KeyEnter
				default:
					ch <- rune(b)
				}
			}
		}
	}()
	return ch
}
