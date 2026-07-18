// Copyright 2018 The goftp Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"net"
	"runtime/debug"
	"strconv"
	"time"
)

// Version returns the library version
func Version() string {
	return "0.3.0"
}

// ServerOpts contains parameters for server.NewServer()
type ServerOpts struct {
	// The factory that will be used to create a new FTPDriver instance for
	// each client connection. This is a mandatory option.
	Factory DriverFactory

	Auth Auth

	// Server Name, Default is Go Ftp Server
	Name string

	// The hostname that the FTP server should listen on. Optional, defaults to
	// "::", which means all hostnames on ipv4 and ipv6.
	Hostname string

	// Public IP of the server
	PublicIp string

	// Passive ports
	PassivePorts string

	// The port that the FTP should listen on. Optional, defaults to 3000. In
	// a production environment you will probably want to change this to 21.
	Port int

	// use tls, default is false
	TLS bool

	// if tls used, cert file is required
	CertFile string

	// if tls used, key file is required
	KeyFile string

	// If ture TLS is used in RFC4217 mode
	ExplicitFTPS bool

	WelcomeMessage string

	// A logger implementation, if nil the StdLogger is used
	Logger Logger

	// A logrus logger for logging authentication requests and more
	LogrusEntry *logrus.Entry

	// MaxConnections bounds the number of concurrent UN-AUTHENTICATED
	// connections (those still in the pre-login command exchange). While
	// saturated the accept loop stops accepting, so excess connections wait in
	// the kernel backlog (backpressure). The slot is released the instant a
	// connection logs in, so established/authenticated sessions are NOT counted
	// against this limit. 0 (the default) means unlimited — existing behaviour.
	// This stops a connection flood from spawning unbounded goroutines.
	MaxConnections int

	// HandshakeTimeout is the maximum time a connection may spend in the
	// pre-login phase (from connect until it authenticates). A client that
	// opens TCP and then stalls (slowloris) is dropped once it elapses, instead
	// of parking a goroutine + socket forever. It is cleared on successful
	// login, so it never bounds an authenticated session's idle time. 0 (the
	// default) disables it — existing behaviour.
	HandshakeTimeout time.Duration
}

// Server is the root of your FTP application. You should instantiate one
// of these and call ListenAndServe() to start accepting client connections.
//
// Always use the NewServer() method to create a new Server.
type Server struct {
	*ServerOpts
	listenTo    string
	logger      Logger
	logrusEntry *logrus.Entry
	listener    net.Listener
	tlsConfig   *tls.Config
	ctx         context.Context
	cancel      context.CancelFunc
	feats       string
	implicitTLS bool
}

// ErrServerClosed is returned by ListenAndServe() or Serve() when a shutdown
// was requested.
var ErrServerClosed = errors.New("ftp: server closed")

// serverOptsWithDefaults copies an ServerOpts struct into a new struct,
// then adds any default values that are missing and returns the new data.
func serverOptsWithDefaults(opts *ServerOpts) *ServerOpts {
	var newOpts ServerOpts
	if opts == nil {
		opts = &ServerOpts{}
	}
	if opts.Hostname == "" {
		newOpts.Hostname = "::"
	} else {
		newOpts.Hostname = opts.Hostname
	}
	if opts.Port == 0 {
		newOpts.Port = 3000
	} else {
		newOpts.Port = opts.Port
	}
	newOpts.Factory = opts.Factory
	if opts.Name == "" {
		newOpts.Name = "Go FTP Server"
	} else {
		newOpts.Name = opts.Name
	}

	if opts.WelcomeMessage == "" {
		newOpts.WelcomeMessage = defaultWelcomeMessage
	} else {
		newOpts.WelcomeMessage = opts.WelcomeMessage
	}

	if opts.Auth != nil {
		newOpts.Auth = opts.Auth
	}

	newOpts.Logger = &StdLogger{}
	if opts.Logger != nil {
		newOpts.Logger = opts.Logger
	}

	newOpts.LogrusEntry = logrus.NewEntry(logrus.New())
	if opts.LogrusEntry != nil {
		newOpts.LogrusEntry = opts.LogrusEntry
	}

	newOpts.TLS = opts.TLS
	newOpts.KeyFile = opts.KeyFile
	newOpts.CertFile = opts.CertFile
	newOpts.ExplicitFTPS = opts.ExplicitFTPS

	newOpts.PublicIp = opts.PublicIp
	newOpts.PassivePorts = opts.PassivePorts

	newOpts.MaxConnections = opts.MaxConnections
	newOpts.HandshakeTimeout = opts.HandshakeTimeout

	return &newOpts
}

// NewServer initialises a new FTP server. Configuration options are provided
// via an instance of ServerOpts. Calling this function in your code will
// probably look something like this:
//
//	factory := &MyDriverFactory{}
//	server  := server.NewServer(&server.ServerOpts{ Factory: factory })
//
// or:
//
//	factory := &MyDriverFactory{}
//	opts    := &server.ServerOpts{
//	  Factory: factory,
//	  Port: 2000,
//	  Hostname: "127.0.0.1",
//	}
//	server  := server.NewServer(opts)
func NewServer(opts *ServerOpts) *Server {
	opts = serverOptsWithDefaults(opts)
	s := new(Server)
	s.ServerOpts = opts
	s.listenTo = net.JoinHostPort(opts.Hostname, strconv.Itoa(opts.Port))
	s.logger = opts.Logger
	s.logrusEntry = opts.LogrusEntry
	return s
}

// NewConn constructs a new object that will handle the FTP protocol over
// an active net.TCPConn. The TCP connection should already be open before
// it is handed to this functions. driver is an instance of FTPDriver that
// will handle all auth and persistence details.
func (server *Server) newConn(tcpConn net.Conn, driver Driver) *Conn {
	c := new(Conn)
	c.namePrefix = "/"
	c.conn = tcpConn
	c.controlReader = bufio.NewReader(tcpConn)
	c.controlWriter = bufio.NewWriter(tcpConn)
	c.driver = driver
	c.auth = server.Auth
	c.server = server
	c.sessionID = newSessionID()
	c.logger = server.logger
	sourceIP, _, _ := net.SplitHostPort(tcpConn.RemoteAddr().String())
	c.logrusEntry = server.logrusEntry.WithField("source_ip", sourceIP)
	c.tlsConfig = server.tlsConfig
	c.tls = server.implicitTLS
	c.handshakeTimeout = server.HandshakeTimeout

	driver.Init(c)
	return c
}

func simpleTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	config := &tls.Config{}
	if config.NextProtos == nil {
		config.NextProtos = []string{"ftp"}
	}

	var err error
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return config, nil
}

// ListenAndServe asks a new Server to begin accepting client connections. It
// accepts no arguments - all configuration is provided via the NewServer
// function.
//
// If the server fails to start for any reason, an error will be returned. Common
// errors are trying to bind to a privileged port or something else is already
// listening on the same port.
func (server *Server) ListenAndServe() error {
	var listener net.Listener
	var err error
	var curFeats = featCmds

	if server.ServerOpts.TLS {
		server.tlsConfig, err = simpleTLSConfig(server.CertFile, server.KeyFile)
		if err != nil {
			return err
		}

		curFeats += " AUTH TLS\r\n PBSZ\r\n PROT\r\n"

		if server.ServerOpts.ExplicitFTPS {
			listener, err = net.Listen("tcp", server.listenTo)
		} else {
			server.implicitTLS = true
			listener, err = tls.Listen("tcp", server.listenTo, server.tlsConfig)
		}
	} else {
		listener, err = net.Listen("tcp", server.listenTo)
	}
	if err != nil {
		return err
	}
	server.feats = fmt.Sprintf(feats, curFeats)

	sessionID := ""
	server.logger.Printf(sessionID, "%s listening on %d", server.Name, server.Port)

	return server.Serve(listener)
}

// Serve accepts connections on a given net.Listener and handles each
// request in a new goroutine.
func (server *Server) Serve(l net.Listener) error {
	server.listener = l
	server.ctx, server.cancel = context.WithCancel(context.Background())
	sessionID := ""

	// Bound concurrent un-authenticated connections. A slot is held only for the
	// pre-login phase (released on login or close), so authenticated sessions
	// don't count against it. nil semaphore ⇒ unlimited (default).
	var sem chan struct{}
	if server.MaxConnections > 0 {
		sem = make(chan struct{}, server.MaxConnections)
	}

	for {
		tcpConn, err := server.listener.Accept()
		if err != nil {
			select {
			case <-server.ctx.Done():
				return ErrServerClosed
			default:
			}
			server.logger.Printf(sessionID, "listening error: %v", err)
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return err
		}

		// Backpressure: block until a pre-login slot is free. While blocked we
		// don't Accept, so further connections queue in the kernel backlog.
		if sem != nil {
			select {
			case sem <- struct{}{}:
			case <-server.ctx.Done():
				tcpConn.Close()
				return ErrServerClosed
			}
		}

		// Set up the connection and launch its handler. This runs in a closure so
		// that a panic BEFORE Conn.Serve() takes ownership — e.g. in
		// Factory.NewDriver or driver.Init (called by newConn) — is recovered
		// here: it releases the pre-login slot and closes the conn instead of
		// unwinding (and killing) the whole accept loop. Once go ftpConn.Serve()
		// is launched, Serve owns the slot release and its own panic recovery.
		func() {
			launched := false
			defer func() {
				r := recover()
				if !launched {
					tcpConn.Close()
					if sem != nil {
						<-sem
					}
				}
				if r != nil {
					server.logger.Printf(sessionID, "recovered panic setting up connection: %v\n%s", r, debug.Stack())
					// Preserve the historical fail-fast behaviour for consumers
					// running WITHOUT the concurrency guard (sem == nil): with no
					// slot to protect there is nothing to leak, so a setup panic
					// propagates exactly as it did before this change. Only when the
					// guard is active do we swallow it — having released the slot —
					// to keep the accept loop alive under the guard's protection.
					if sem == nil {
						panic(r)
					}
				}
			}()

			driver, err := server.Factory.NewDriver()
			if err != nil {
				server.logger.Printf(sessionID, "Error creating driver, aborting client connection: %v", err)
				return
			}
			ftpConn := server.newConn(tcpConn, driver)
			if sem != nil {
				ftpConn.releaseSlot = func() { <-sem }
			}
			go ftpConn.Serve()
			launched = true
		}()
	}
}

// Shutdown will gracefully stop a server. Already connected clients will retain their connections
func (server *Server) Shutdown() error {
	if server.cancel != nil {
		server.cancel()
	}
	if server.listener != nil {
		return server.listener.Close()
	}
	// server wasnt even started
	return nil
}
