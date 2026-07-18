// Copyright 2018 The goftp Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package server

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// mockDriver is a no-op Driver for the fork's own tests: it accepts any login
// and never touches storage. The overload tests exercise only the accept loop
// and pre-login phase, so the file operations are never called.
type mockDriver struct{}

func (mockDriver) Init(*Conn) {}
func (mockDriver) CheckUser(string) (bool, *Permissions, string, error) {
	p := Permissions{}
	return true, &p, "", nil
}
func (mockDriver) Login(string, *Permissions) (bool, *logrus.Entry, Logger, error) {
	return true, nil, nil, nil
}
func (mockDriver) LoginSuccess(string, *Permissions)          {}
func (mockDriver) LoginFail(string, *Permissions)             {}
func (mockDriver) Stat(string) (FileInfo, error)              { return nil, errors.New("not implemented") }
func (mockDriver) ChangeDir(string) error                     { return nil }
func (mockDriver) ListDir(string, func(FileInfo) error) error { return nil }
func (mockDriver) DeleteDir(string) error                     { return nil }
func (mockDriver) DeleteFile(string) error                    { return nil }
func (mockDriver) Rename(string, string) error                { return nil }
func (mockDriver) MakeDir(string) error                       { return nil }
func (mockDriver) GetFile(string, int64) (int64, io.ReadCloser, error) {
	return 0, nil, errors.New("not implemented")
}
func (mockDriver) PutFile(string, io.Reader, bool) (int64, error) {
	return 0, errors.New("not implemented")
}

type mockFactory struct{}

func (mockFactory) NewDriver() (Driver, error) { return mockDriver{}, nil }

// panicInitDriver panics in Init to exercise the accept-loop's panic recovery.
type panicInitDriver struct{ mockDriver }

func (panicInitDriver) Init(*Conn) { panic("boom in Init") }

// panicOnceFactory returns a driver that panics in Init on the first N
// connections, then healthy drivers, so a test can prove the accept loop
// survives the panic and still serves later connections.
type panicOnceFactory struct{ remaining *int32 }

func (f panicOnceFactory) NewDriver() (Driver, error) {
	if atomic.AddInt32(f.remaining, -1) >= 0 {
		return panicInitDriver{}, nil
	}
	return mockDriver{}, nil
}

// blockingLoginDriver accepts login but blocks in LoginSuccess (a post-auth
// callback) until released, to prove the pre-login slot is freed BEFORE that
// callback runs.
type blockingLoginDriver struct {
	mockDriver
	block chan struct{}
}

func (d blockingLoginDriver) LoginSuccess(string, *Permissions) { <-d.block }

type blockingLoginFactory struct{ block chan struct{} }

func (f blockingLoginFactory) NewDriver() (Driver, error) {
	return blockingLoginDriver{block: f.block}, nil
}

// mockAuth accepts admin/admin and returns a non-nil Permissions (the fork's
// PASS handler dereferences it).
type mockAuth struct{}

func (mockAuth) CheckPasswd(name, pass string) (bool, *Permissions, error) {
	p := Permissions{}
	return name == "admin" && pass == "admin", &p, nil
}

// startOverloadServer starts a plain-FTP server on an ephemeral port with the
// given overload guards and returns its address plus a shutdown func. It uses
// Serve(listener) directly (no TLS) so the test learns the chosen port and
// exercises the exact accept loop + Conn.Serve path the guards live in.
func startOverloadServer(t *testing.T, maxConns int, handshakeTimeout time.Duration) (string, func()) {
	t.Helper()
	opt := &ServerOpts{
		Name:             "overload test ftpd",
		Factory:          mockFactory{},
		Auth:             mockAuth{},
		Logger:           new(DiscardLogger),
		MaxConnections:   maxConns,
		HandshakeTimeout: handshakeTimeout,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := NewServer(opt)
	go func() { _ = s.Serve(ln) }()
	return ln.Addr().String(), func() { _ = s.Shutdown() }
}

// readBanner reads the 220 greeting the server sends on connect.
func readBanner(t *testing.T, br *bufio.Reader, conn net.Conn) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading 220 banner: %v", err)
	}
	if !strings.HasPrefix(line, "220") {
		t.Fatalf("expected 220 banner, got %q", line)
	}
	return line
}

// TestFTPHandshakeTimeout proves guard #2 for FTP: a client that connects and
// then stalls (never authenticates) is dropped once HandshakeTimeout elapses,
// instead of parking a goroutine + socket forever.
func TestFTPHandshakeTimeout(t *testing.T) {
	addr, stop := startOverloadServer(t, 0, 300*time.Millisecond)
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	br := bufio.NewReader(conn)
	readBanner(t, br, conn) // greeting arrives...

	// ...then we send nothing. The server must close us shortly after the
	// deadline rather than hanging forever.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	if _, err := br.ReadString('\n'); err == nil {
		t.Fatal("expected the stalled connection to be dropped, but the read succeeded")
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("connection dropped after %v — deadline not enforced promptly", elapsed)
	}
}

// TestFTPMaxConnections proves guard #1 for FTP: no more than MaxConnections
// un-authenticated connections are served at once; a further connection is held
// off (no greeting) until an existing pre-login slot frees.
func TestFTPMaxConnections(t *testing.T) {
	addr, stop := startOverloadServer(t, 2, 0)
	defer stop()

	// Two connections that read their greeting but never log in occupy both
	// pre-login slots.
	dialHold := func() (net.Conn, *bufio.Reader) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		br := bufio.NewReader(c)
		readBanner(t, br, c)
		return c, br
	}
	c1, _ := dialHold()
	defer c1.Close()
	c2, _ := dialHold()
	defer c2.Close()

	// A third connection: TCP connects (kernel backlog), but the server should
	// not accept/serve it — so no greeting arrives — while both slots are full.
	c3, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial c3: %v", err)
	}
	defer c3.Close()
	br3 := bufio.NewReader(c3)
	_ = c3.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if _, err := br3.ReadString('\n'); err == nil {
		t.Fatal("third connection was served while both pre-login slots were full (cap not enforced)")
	}

	// Free a slot; the third connection must now be served.
	c1.Close()
	readBanner(t, br3, c3)
}

// TestFTPSlotReleasedOnLogin proves the design boundary of guard #1: the
// pre-login slot is released when a connection authenticates, so authenticated
// sessions do NOT count against MaxConnections (otherwise a busy server would
// refuse new logins). With a cap of 1, a second client must still be able to
// connect and log in while the first session stays open.
func TestFTPSlotReleasedOnLogin(t *testing.T) {
	addr, stop := startOverloadServer(t, 1, 0)
	defer stop()

	login := func() (net.Conn, *bufio.Reader) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		br := bufio.NewReader(c)
		readBanner(t, br, c)
		sendCmd(t, c, br, "USER admin", "331")
		sendCmd(t, c, br, "PASS admin", "230")
		return c, br
	}

	// First client logs in and holds the session open.
	c1, _ := login()
	defer c1.Close()

	// Second client must still get through (the slot was freed on c1's login).
	done := make(chan struct{})
	go func() {
		c2, _ := login()
		_ = c2.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("second client could not connect+login — the slot was not released on login")
	}
}

// TestFTPDriverInitPanicDoesNotLeakOrWedge proves the accept loop survives a
// panic in driver.Init (raised inside newConn, before Conn.Serve() takes over):
// the pre-login slot must be released and the loop must keep serving. With a cap
// of 1, if the panicking connection leaked its slot, no later connection could
// ever be served.
func TestFTPDriverInitPanicDoesNotLeakOrWedge(t *testing.T) {
	remaining := int32(1) // first connection panics in Init, rest are healthy
	opt := &ServerOpts{
		Name:           "panic test ftpd",
		Factory:        panicOnceFactory{remaining: &remaining},
		Auth:           mockAuth{},
		Logger:         new(DiscardLogger),
		MaxConnections: 1,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := NewServer(opt)
	go func() { _ = s.Serve(ln) }()
	defer func() { _ = s.Shutdown() }()
	addr := ln.Addr().String()

	// First connection triggers the Init panic; it should be closed and its slot
	// released without killing the loop.
	c0, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial c0: %v", err)
	}
	_ = c0.Close()

	// A subsequent connection must still be served (banner arrives) — proving the
	// single slot was freed and the accept loop is alive.
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			br := bufio.NewReader(c)
			_ = c.SetReadDeadline(time.Now().Add(1 * time.Second))
			line, rerr := br.ReadString('\n')
			_ = c.Close()
			if rerr == nil && strings.HasPrefix(line, "220") {
				return // healthy — loop survived the panic and the slot was freed
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("accept loop did not serve a healthy connection after a driver.Init panic (slot leaked or loop died)")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestFTPCommandLineLengthCapped proves a client cannot exhaust memory by
// streaming a command line with no newline: the control reader is bounded to
// maxCommandLine bytes, after which the connection is dropped.
func TestFTPCommandLineLengthCapped(t *testing.T) {
	addr, stop := startOverloadServer(t, 0, 0) // guards off — isolate the line cap
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	readBanner(t, br, conn)

	// Stream 16 KiB with no newline (> the 8 KiB cap).
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	junk := make([]byte, 16*1024)
	for i := range junk {
		junk[i] = 'A'
	}
	_, _ = conn.Write(junk)

	// The server must hit the cap and close, not keep buffering.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := br.ReadString('\n'); err == nil {
		t.Fatal("expected the connection to be dropped after an over-long command line")
	}
}

// TestFTPSetupPanicPropagatesWhenGuardOff proves the backward-compatibility
// carve-out: with the concurrency guard OFF (MaxConnections == 0) a panic during
// connection setup (driver.Init) still propagates out of Serve (fail-fast), as it
// did before the guard existed — it is only swallowed when the guard is active.
func TestFTPSetupPanicPropagatesWhenGuardOff(t *testing.T) {
	remaining := int32(1) // first connection panics in Init
	opt := &ServerOpts{
		Name:           "fail-fast test ftpd",
		Factory:        panicOnceFactory{remaining: &remaining},
		Auth:           mockAuth{},
		Logger:         new(DiscardLogger),
		MaxConnections: 0, // guard OFF
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	s := NewServer(opt)
	panicked := make(chan interface{}, 1)
	go func() {
		defer func() { panicked <- recover() }()
		_ = s.Serve(ln)
	}()

	if c, derr := net.Dial("tcp", ln.Addr().String()); derr == nil {
		_ = c.Close()
	}

	select {
	case r := <-panicked:
		if r == nil {
			t.Fatal("expected the setup panic to propagate out of Serve when the guard is off")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve swallowed the panic with the guard off — fail-fast behaviour was not preserved")
	}
}

// TestFTPSlotReleasedBeforeLoginSuccess proves the pre-login slot is released at
// the authentication transition — before the 230 write and the LoginSuccess
// callback — not after Conn.Serve regains control. Otherwise a client whose 230
// flush blocks, or a driver whose LoginSuccess blocks, would pin the slot. With a
// cap of 1 and a LoginSuccess that blocks forever, a second client must still be
// able to connect.
func TestFTPSlotReleasedBeforeLoginSuccess(t *testing.T) {
	block := make(chan struct{})
	defer close(block)

	opt := &ServerOpts{
		Name:           "blocking-loginsuccess ftpd",
		Factory:        blockingLoginFactory{block: block},
		Auth:           mockAuth{},
		Logger:         new(DiscardLogger),
		MaxConnections: 1,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := NewServer(opt)
	go func() { _ = s.Serve(ln) }()
	defer func() { _ = s.Shutdown() }()
	addr := ln.Addr().String()

	// Client 1 logs in fully; its session goroutine then blocks in LoginSuccess.
	c1, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial c1: %v", err)
	}
	defer c1.Close()
	br1 := bufio.NewReader(c1)
	readBanner(t, br1, c1)
	sendCmd(t, c1, br1, "USER admin", "331")
	sendCmd(t, c1, br1, "PASS admin", "230") // 230 is written before LoginSuccess blocks

	// The single slot must already be free even though c1 is stuck in LoginSuccess.
	done := make(chan struct{})
	go func() {
		c2, derr := net.Dial("tcp", addr)
		if derr != nil {
			return
		}
		defer c2.Close()
		br2 := bufio.NewReader(c2)
		_ = c2.SetReadDeadline(time.Now().Add(1 * time.Second))
		if line, rerr := br2.ReadString('\n'); rerr == nil && strings.HasPrefix(line, "220") {
			close(done)
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("second client not served — the pre-login slot was held during a blocking LoginSuccess")
	}
}

// sendCmd writes an FTP command and asserts the reply code prefix.
func sendCmd(t *testing.T, conn net.Conn, br *bufio.Reader, cmd, wantCode string) {
	t.Helper()
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(cmd + "\r\n")); err != nil {
		t.Fatalf("write %q: %v", cmd, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading reply to %q: %v", cmd, err)
	}
	if !strings.HasPrefix(line, wantCode) {
		t.Fatalf("reply to %q = %q, want code %s", cmd, line, wantCode)
	}
}
