// Copyright 2018 The goftp Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package server

import (
	"github.com/sirupsen/logrus"
	"io"
)

// DriverFactory is a driver factory to create driver. For each client that connects to the server, a new FTPDriver is required.
// Create an implementation if this interface and provide it to FTPServer.
type DriverFactory interface {
	NewDriver() (Driver, error)
}

// Driver is an interface that you will create an implementation that speaks to your
// chosen persistence layer. graval will create a new instance of your
// driver for each client that connects and delegate to it as required.
type Driver interface {
	// Init init
	Init(*Conn)

	// params  - the username that is about to authenticate,
	//         - but before actually authenticating with Auth backend
	// returns - bool whether the user should continue to login or not
	//         - string that shows the uuid of the user (if available)
	//         - string that shows the reason if the user cannot login
	//         - an error if the login cannot be processed
	CheckUser(string) (bool, *Permissions, string, error)

	// params  - the username that just authenticated successfuly,
	//         - but before actually logging into the server
	// returns - bool whether the user should continue to login or not
	//         - logrus.Entry that should be used for logging information for this connection
	//         - an error if the login cannot be processed
	Login(string, *Permissions) (bool, *logrus.Entry, Logger, error)

	// params  - the username that logged in entirely successfuly, and any perms that were generated
	LoginSuccess(string, *Permissions)

	// params  - the username that failed to login, and any perms that were generated
	LoginFail(string, *Permissions)

	// params  - a file path
	// returns - a time indicating when the requested path was last modified
	//         - an error if the file doesn't exist or the user lacks
	//           permissions
	Stat(string) (FileInfo, error)

	// params  - path
	// returns - true if the current user is permitted to change to the
	//           requested path
	ChangeDir(string) error

	// params  - path, function on file or subdir found
	// returns - error
	//           path
	ListDir(string, func(FileInfo) error) error

	// params  - path
	// returns - nil if the directory was deleted or any error encountered
	DeleteDir(string) error

	// params  - path
	// returns - nil if the file was deleted or any error encountered
	DeleteFile(string) error

	// params  - from_path, to_path
	// returns - nil if the file was renamed or any error encountered
	Rename(string, string) error

	// params  - path
	// returns - nil if the new directory was created or any error encountered
	MakeDir(string) error

	// params  - path
	// returns - a string containing the file data to send to the client
	GetFile(string, int64) (int64, io.ReadCloser, error)

	// params  - destination path, an io.Reader containing the file data
	// returns - the number of bytes writen and the first error encountered while writing, if any.
	PutFile(string, io.Reader, bool) (int64, error)
}
