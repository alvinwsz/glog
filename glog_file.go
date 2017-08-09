// Go support for leveled logs, analogous to https://code.google.com/p/google-glog/
//
// Copyright 2013 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// File I/O for logs.

package glog

import (
	"flag"
	"fmt"
	//"github.com/alvinwsz/flag"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	_         = iota
	KB uint64 = 1 << (iota * 10)
	MB
	GB
	TB
)

// MaxSize(MB) is the maximum size of a log file in Mbytes.
var MaxSize uint64 = 100

func getProgramName() string {
	base := filepath.Base(os.Args[0])
	ext := filepath.Ext(base)
	return strings.TrimSuffix(base, ext)
}

var (
	pid      = os.Getpid()
	host     = "unknownhost"
	userName = "unknownuser"
	logDir   = os.TempDir()
	logFile  = getProgramName() + ".log"
)

func init() {
	flag.StringVar(&logDir, "log_dir", os.TempDir(), "If non-empty, write log files in this directory")
	flag.StringVar(&logFile, "log_file", getProgramName()+".log", "If non-empty, it is used as the log file name")
	flag.Uint64Var(&MaxSize, "log_max_size", 100, "the maximum size of a log file in Mbytes")
	h, err := os.Hostname()
	if err == nil {
		host = shortHostname(h)
	}

	current, err := user.Current()
	if err == nil {
		userName = current.Username
	}

	// Sanitize userName since it may contain filepath separators on Windows.
	userName = strings.Replace(userName, `\`, "_", -1)
}

// shortHostname returns its argument, truncating at the first period.
// For instance, given "www.google.com" it returns "www".
func shortHostname(hostname string) string {
	if i := strings.Index(hostname, "."); i >= 0 {
		return hostname[:i]
	}
	return hostname
}

// logName returns a new log file name containing tag, with start time t, and
// the name for the symlink for tag.
func logName(t time.Time) (name, link string) {
	name = fmt.Sprintf("%s.%s.%s.%04d%02d%02d-%02d%02d%02d.%d",
		logFile,
		host,
		userName,
		t.Year(),
		t.Month(),
		t.Day(),
		t.Hour(),
		t.Minute(),
		t.Second(),
		pid)
	return name, logFile
}

var onceLogDirs sync.Once

// create creates a new log file and returns the file and its filename, which
// contains tag ("INFO", "FATAL", etc.) and t.  If the file is created
// successfully, create also attempts to update the symlink for that tag, ignoring
// errors.
func create(t time.Time) (f *os.File, filename string, err error) {
	name, link := logName(t)
	var lastErr error
	fname := filepath.Join(logDir, name)
	f, err = os.Create(fname)
	fmt.Println("file created: ", fname, "  f= ", f, "  err=", err)
	if err == nil {
		symlink := filepath.Join(logDir, link)
		os.Remove(symlink)        // ignore err
		os.Symlink(name, symlink) // ignore err
		fmt.Println("symlink created: ", symlink)
		return f, fname, nil
	}
	lastErr = err
	return nil, "", fmt.Errorf("log: cannot create log: %v", lastErr)
}
