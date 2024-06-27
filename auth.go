// Copyright 2018 The goftp Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package server

// Permissions is a map name value pair to store users data
// upon successful login.
type Permissions map[string]string

// Auth is an interface to auth your ftp user login.
type Auth interface {
	CheckPasswd(string, string) (bool, *Permissions, error)
}

var (
	_ Auth = &SimpleAuth{}
)

// SimpleAuth implements Auth interface to provide a memory user login auth
type SimpleAuth struct {
	Name     string
	Password string
}

// CheckPasswd will check user's password
func (a *SimpleAuth) CheckPasswd(name, pass string) (bool, *Permissions, error) {
	if name != a.Name || pass != a.Password {
		return false, nil, nil
	}
	return true, nil, nil
}
