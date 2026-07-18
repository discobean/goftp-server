// Copyright 2018 The goftp Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package server

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultWelcomeMessage = "Welcome to the Go FTP Server"

	// maxCommandLine caps a single control-connection command line. FTP commands
	// (incl. long paths) are short; without a cap, bufio.ReadString('\n') would
	// grow an arbitrarily large buffer for a client that streams bytes without a
	// newline — a cheap way to exhaust process memory. 8 KiB comfortably exceeds
	// any legitimate command/path while bounding the allocation.
	maxCommandLine = 8192
)

type Conn struct {
	conn          net.Conn
	controlReader *bufio.Reader
	controlWriter *bufio.Writer
	dataConn      DataSocket
	driver        Driver
	auth          Auth
	logger        Logger
	logrusEntry   *logrus.Entry
	server        *Server
	tlsConfig     *tls.Config
	sessionID     string
	namePrefix    string
	reqUser       string
	user          string
	renameFrom    string
	lastFilePos   int64
	appendData    bool
	closed        bool
	tls           bool

	// Overload guards (see ServerOpts.HandshakeTimeout / MaxConnections).
	// handshakeTimeout bounds the pre-login phase; releaseSlot frees this
	// connection's pre-login concurrency slot and is run at most once (on login
	// or teardown, whichever comes first).
	handshakeTimeout time.Duration
	releaseSlot      func()
	releaseOnce      sync.Once
}

// releaseHandshakeSlot frees the pre-login concurrency slot exactly once. Safe
// to call when no limit is configured (releaseSlot is nil).
func (conn *Conn) releaseHandshakeSlot() {
	if conn.releaseSlot != nil {
		conn.releaseOnce.Do(conn.releaseSlot)
	}
}

// clearPreLoginDeadline removes the pre-login handshake deadline. It is called
// the instant authentication succeeds — BEFORE the success response (e.g. FTP
// 230) is written — so that a slow-but-successful login (one whose backend auth
// took most of the deadline window) can still deliver its response instead of
// having the write fail against an already-expired deadline. Idempotent.
func (conn *Conn) clearPreLoginDeadline() {
	if conn.handshakeTimeout > 0 {
		_ = conn.conn.SetDeadline(time.Time{})
		conn.handshakeTimeout = 0
	}
}

func (conn *Conn) SessionID() string {
	return conn.sessionID
}

func (conn *Conn) RemoteAddr() net.Addr {
	return conn.conn.RemoteAddr()
}

// Returns true if connection has been upgraded explicitly to FTP/S,
// or connection is implicit FTP/s
// Returns false if connection is just regular plain FTP
func (conn *Conn) IsConnectionSecure() bool {
	return conn.tls
}

func (conn *Conn) IsTLS() bool {
	return (conn.tls || conn.tlsConfig != nil)
}

func (conn *Conn) LoginUser() string {
	return conn.user
}

func (conn *Conn) IsLogin() bool {
	return len(conn.user) > 0
}

func (conn *Conn) PublicIp() string {
	return conn.server.PublicIp
}

func (conn *Conn) passiveListenIP() string {
	var listenIP string
	if len(conn.PublicIp()) > 0 {
		listenIP = conn.PublicIp()
	} else {
		listenIP = conn.conn.LocalAddr().(*net.TCPAddr).IP.String()
	}

	lastIdx := strings.LastIndex(listenIP, ":")
	if lastIdx <= 0 {
		return listenIP
	}
	return listenIP[:lastIdx]
}

func (conn *Conn) PassivePort() int {
	if len(conn.server.PassivePorts) > 0 {
		portRange := strings.Split(conn.server.PassivePorts, "-")

		if len(portRange) != 2 {
			log.Println("empty port")
			return 0
		}

		minPort, _ := strconv.Atoi(strings.TrimSpace(portRange[0]))
		maxPort, _ := strconv.Atoi(strings.TrimSpace(portRange[1]))

		return minPort + mrand.Intn(maxPort-minPort)
	}
	// let system automatically chose one port
	return 0
}

// returns a random 20 char string that can be used as a unique session ID
func newSessionID() string {
	hash := sha256.New()
	_, err := io.CopyN(hash, rand.Reader, 50)
	if err != nil {
		return "????????????????????"
	}
	md := hash.Sum(nil)
	mdStr := hex.EncodeToString(md)
	return mdStr[0:20]
}

// Serve starts an endless loop that reads FTP commands from the client and
// responds appropriately. terminated is a channel that will receive a true
// message when the connection closes. This loop will be running inside a
// goroutine, so use this channel to be notified when the connection can be
// cleaned up.
func (conn *Conn) Serve() {
	// Backstop: a panic in any command handler (e.g. a driver/storage call) must
	// not crash the whole FTP server. Recover, log internally, and ensure the
	// connection is closed. Per-command recovery in receiveLine handles the
	// common case gracefully; this catches anything outside that path.
	defer func() {
		if r := recover(); r != nil {
			conn.logger.Printf(conn.sessionID, "recovered panic in connection: %v\n%s", r, debug.Stack())
			conn.Close()
		}
	}()
	// Free the pre-login slot on the way out, covering connections that
	// disconnect before ever authenticating (it's a no-op if login already
	// released it, or if no limit is configured).
	defer conn.releaseHandshakeSlot()

	// Bound the pre-login phase against a stalled (slowloris) client. We set BOTH
	// the read and write deadline (SetDeadline, not SetReadDeadline): a client can
	// otherwise send commands but never read our replies, filling the socket send
	// buffer until writeMessage's Flush blocks forever — a write stall a read-only
	// deadline can't interrupt, which would hold the pre-login slot indefinitely.
	// Set on the raw control connection; it carries through an AUTH TLS upgrade
	// (the deadline lives on the underlying socket) and is cleared on login below.
	if conn.handshakeTimeout > 0 {
		_ = conn.conn.SetDeadline(time.Now().Add(conn.handshakeTimeout))
	}

	conn.logger.Print(conn.sessionID, "Connection Established")
	// send welcome
	conn.writeMessage(220, conn.server.WelcomeMessage)
	// read commands
	for {
		line, err := conn.readCommandLine()
		if err != nil {
			if err != io.EOF {
				conn.logger.Print(conn.sessionID, fmt.Sprint("read error:", err))
			}

			break
		}
		conn.receiveLine(line)
		// QUIT command closes connection, break to avoid error on reading from
		// closed socket
		if conn.closed == true {
			break
		}
		// On successful login, leave the pre-login regime: drop the deadline (so
		// an established session isn't bounded by it) and release the pre-login
		// concurrency slot. The deadline is normally already cleared at the login
		// point (see commandPass) so the 230 write isn't bounded; this is an
		// idempotent backstop that also covers any other path that sets conn.user.
		if conn.IsLogin() {
			conn.clearPreLoginDeadline()
			conn.releaseHandshakeSlot()
		}
	}
	conn.Close()
	conn.logger.Print(conn.sessionID, "Connection Terminated")
}

// Close will manually close this connection, even if the client isn't ready.
func (conn *Conn) Close() {
	conn.conn.Close()
	conn.closed = true
	if conn.dataConn != nil {
		conn.dataConn.Close()
		conn.dataConn = nil
	}
}

func (conn *Conn) upgradeToTLS() error {
	conn.logger.Print(conn.sessionID, "Upgrading connectiion to TLS")
	tlsConn := tls.Server(conn.conn, conn.tlsConfig)
	err := tlsConn.Handshake()
	if err == nil {
		conn.conn = tlsConn
		conn.controlReader = bufio.NewReader(tlsConn)
		conn.controlWriter = bufio.NewWriter(tlsConn)
		conn.tls = true
	}
	return err
}

// receiveLine accepts a single line FTP command and co-ordinates an
// appropriate response.
func (conn *Conn) receiveLine(line string) {
	command, param := conn.parseLine(line)
	conn.logger.PrintCommand(conn.sessionID, command, param)
	cmdObj := commands[strings.ToUpper(command)]
	if cmdObj == nil {
		conn.writeMessage(500, "Command not found")
		return
	}
	if cmdObj.RequireParam() && param == "" {
		conn.writeMessage(553, "action aborted, required param missing")
	} else if cmdObj.RequireAuth() && conn.user == "" {
		conn.writeMessage(530, "not logged in")
	} else {
		// Recover per command so a panic in a driver/storage call fails just
		// this operation with a clean 550 and keeps the FTP session alive,
		// rather than crashing the server.
		func() {
			defer func() {
				if r := recover(); r != nil {
					conn.logger.Printf(conn.sessionID, "recovered panic in command %s: %v\n%s", command, r, debug.Stack())
					conn.writeMessage(550, "Action aborted, internal error")
				}
			}()
			cmdObj.Execute(conn, param)
		}()
	}
}

// readCommandLine reads one command line from the control connection, bounded to
// maxCommandLine bytes. It reads a byte at a time through the buffered
// controlReader (cheap — the buffering is in bufio), so memory is capped as it
// goes: a client that streams data without a newline hits the limit and gets an
// error (the caller then tears the connection down) instead of growing an
// unbounded buffer the way bufio.ReadString('\n') would.
func (conn *Conn) readCommandLine() (string, error) {
	var b strings.Builder
	for {
		c, err := conn.controlReader.ReadByte()
		if err != nil {
			return b.String(), err
		}
		b.WriteByte(c)
		if c == '\n' {
			return b.String(), nil
		}
		if b.Len() >= maxCommandLine {
			return b.String(), fmt.Errorf("command line exceeds %d-byte limit", maxCommandLine)
		}
	}
}

func (conn *Conn) parseLine(line string) (string, string) {
	params := strings.SplitN(strings.Trim(line, "\r\n"), " ", 2)
	if len(params) == 1 {
		return params[0], ""
	}
	return params[0], strings.TrimSpace(params[1])
}

// writeMessage will send a standard FTP response back to the client.
func (conn *Conn) writeMessage(code int, message string) (wrote int, err error) {
	conn.logger.PrintResponse(conn.sessionID, code, message)
	line := fmt.Sprintf("%d %s\r\n", code, message)
	wrote, err = conn.controlWriter.WriteString(line)
	conn.controlWriter.Flush()
	return
}

// writeMessage will send a standard FTP response back to the client.
func (conn *Conn) writeMessageMultiline(code int, message string) (wrote int, err error) {
	conn.logger.PrintResponse(conn.sessionID, code, message)
	line := fmt.Sprintf("%d-%s\r\n%d END\r\n", code, strings.TrimRight(message, "\r\n "), code)
	wrote, err = conn.controlWriter.WriteString(line)
	conn.controlWriter.Flush()
	return
}

// buildPath takes a client supplied path or filename and generates a safe
// absolute path within their account sandbox.
//
//	buildpath("/")
//	=> "/"
//	buildpath("one.txt")
//	=> "/one.txt"
//	buildpath("/files/two.txt")
//	=> "/files/two.txt"
//	buildpath("files/two.txt")
//	=> "/files/two.txt"
//	buildpath("/../../../../etc/passwd")
//	=> "/etc/passwd"
//
// The driver implementation is responsible for deciding how to treat this path.
// Obviously they MUST NOT just read the path off disk. The probably want to
// prefix the path with something to scope the users access to a sandbox.
func (conn *Conn) buildPath(filename string) (fullPath string) {
	if len(filename) > 0 && filename[0:1] == "/" {
		fullPath = filepath.Clean(filename)
	} else if len(filename) > 0 && filename != "-a" {
		fullPath = filepath.Clean(conn.namePrefix + "/" + filename)
	} else {
		fullPath = filepath.Clean(conn.namePrefix)
	}
	fullPath = strings.Replace(fullPath, "//", "/", -1)
	fullPath = strings.Replace(fullPath, string(filepath.Separator), "/", -1)
	return
}

// sendOutofbandData will send a string to the client via the currently open
// data socket. Assumes the socket is open and ready to be used.
func (conn *Conn) sendOutofbandData(data []byte) {
	bytes := len(data)
	if conn.dataConn != nil {
		conn.dataConn.Write(data)
		conn.dataConn.Close()
		conn.dataConn = nil
	}
	message := "Closing data connection, sent " + strconv.Itoa(bytes) + " bytes"
	conn.writeMessage(226, message)
}

func (conn *Conn) sendOutofBandDataWriter(data io.ReadCloser) error {
	conn.lastFilePos = 0
	if conn.dataConn == nil {
		return fmt.Errorf("data connection not available")
	}

	bytes, err := io.Copy(conn.dataConn, data)
	if err != nil {
		conn.dataConn.Close()
		conn.dataConn = nil
		return err
	}
	message := "Closing data connection, sent " + strconv.Itoa(int(bytes)) + " bytes"
	conn.writeMessage(226, message)
	conn.dataConn.Close()
	conn.dataConn = nil

	return nil
}
