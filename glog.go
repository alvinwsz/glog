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

// Package glog implements logging analogous to the Google-internal C++ INFO/ERROR/V setup.
// It provides functions Info, Warning, Error, Fatal, plus formatting variants such as
// Infof. It also provides V-style logging controlled by the -v and -vmodule=file=2 flags.
//
// Basic examples:
//
//	glog.Info("Prepare to repel boarders")
//
//	glog.Fatalf("Initialization failed: %s", err)
//
// See the documentation for the V function for an explanation of these examples:
//
//	if glog.V(2) {
//		glog.Info("Starting transaction...")
//	}
//
//	glog.V(2).Infoln("Processed", nItems, "elements")
//
// Log output is buffered and written periodically using Flush. Programs
// should call Flush before exiting to guarantee all log output is written.
//
// By default, all log statements write to files in a temporary directory.
// This package provides several flags that modify this behavior.
// As a result, flag.Parse must be called before any logging is done.
//
//	-logtostderr=false
//		Logs are written to standard error instead of to files.
//	-alsologtostderr=false
//		Logs are written to standard error as well as to files.
//	-stderrthreshold=ERROR
//		Log events at or above this severity are logged to standard
//		error as well as to files.
//	-log_dir=""
//		Log files will be written to this directory instead of the
//		default temporary directory.
//
//	Other flags provide aids to debugging.
//
//	-log_backtrace_at=""
//		When set to a file and line number holding a logging statement,
//		such as
//			-log_backtrace_at=gopherflakes.go:234
//		a stack trace will be written to the Info log whenever execution
//		hits that statement. (Unlike with -vmodule, the ".go" must be
//		present.)
//	-v=0
//		Enable V-leveled logging at the specified level.
//	-vmodule=""
//		The syntax of the argument is a comma-separated list of pattern=N,
//		where pattern is a literal file name (minus the ".go" suffix) or
//		"glob" pattern and N is a V level. For instance,
//			-vmodule=gopher*=3
//		sets the V level to 3 in all Go files whose names begin "gopher".
//
package glog

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	//stdLog "log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// severity identifies the sort of log: info, warning etc. It also implements
// the flag.Value interface. The -stderrthreshold flag is of type severity and
// should be modified only through the flag.Value interface. The values match
// the corresponding constants in C++.
type severity int32 // sync/atomic int32

// These constants identify the log levels in order of increasing severity.
// A message written to a high-severity log file is also written to each
// lower-severity log file.
const (
	DEBUG severity = iota
	INFO
	WARN
	ERROR
	FATAL
	numSeverity = 5
)

var severityName = []string{
	DEBUG: "DEBUG",
	INFO:  "INFO",
	WARN:  "WARN",
	ERROR: "ERROR",
	FATAL: "FATAL",
}

// get returns the value of the severity.
func (s *severity) get() severity {
	return severity(atomic.LoadInt32((*int32)(s)))
}

// set sets the value of the severity.
func (s *severity) set(val severity) {
	atomic.StoreInt32((*int32)(s), int32(val))
}

// String is part of the flag.Value interface.
func (s *severity) String() string {
	//return strconv.FormatInt(int64(*s), 10)
	return severityName[*s]
}

// Get is part of the flag.Value interface.
func (s *severity) Get() interface{} {
	return *s
}

var errSeveritySyntax = errors.New("syntax error: expected severity:debug/info/warn/error/fatal")

// Set is part of the flag.Value interface.
// used in "-v=severity" or "-vm=file:severity"
func (s *severity) Set(value string) error {
	// Is it a known name?
	v, err := severityByName(value)
	if err == nil {
		s.set(v)
	}
	return err
}

func severityByName(s string) (severity, error) {
	s = strings.ToUpper(s)
	for i, name := range severityName {
		if name == s {
			return severity(i), nil
		}
	}
	return 0, errSeveritySyntax
}

// added by alvin to support -log_to flag
//
type outputFlag int32

const (
	Log2Std outputFlag = 1 << (iota)
	Log2File
	LogDailyRolling
)

// "std" or "file" or "std,file"
func outputFlagByName(s string) (outputFlag, bool) {
	parts := strings.Split(s, ",")
	var of outputFlag
	of = 0
	for _, v := range parts {
		v = strings.ToLower(v)
		if v == "std" {
			of |= Log2Std
		} else if v == "file" {
			of |= Log2File
		} else {
			return 0, false
		}
	}
	return of, true
}

// get returns the value of the severity.
func (s *outputFlag) get() outputFlag {
	return outputFlag(atomic.LoadInt32((*int32)(s)))
}

// set sets the value of the severity.
func (s *outputFlag) set(val outputFlag) {
	atomic.StoreInt32((*int32)(s), int32(val))
}

// String is part of the flag.Value interface.
func (s *outputFlag) String() string {
	return strconv.FormatInt(int64(*s), 10)
}

// Get is part of the flag.Value interface.
func (s *outputFlag) Get() interface{} {
	return *s
}

// Set is part of the flag.Value interface.
// used in "-log_to=std,file"
func (s *outputFlag) Set(value string) error {
	v, ok := outputFlagByName(value)
	if !ok {
		return errors.New("Error: -log_to flag should be std/file or both")
	}
	s.set(v)
	return nil
}

// OutputStats tracks the number of output lines and bytes written.
type OutputStats struct {
	lines int64
	bytes int64
}

// Lines returns the number of lines written.
func (s *OutputStats) Lines() int64 {
	return atomic.LoadInt64(&s.lines)
}

// Bytes returns the number of bytes written.
func (s *OutputStats) Bytes() int64 {
	return atomic.LoadInt64(&s.bytes)
}

// Stats tracks the number of lines of output and number of bytes
// per severity level. Values must be read with atomic.LoadInt64.
var Stats struct {
	Debug, Info, Warning, Error OutputStats
}

var severityStats = [numSeverity]*OutputStats{
	DEBUG: &Stats.Debug,
	INFO:  &Stats.Info,
	WARN:  &Stats.Warning,
	ERROR: &Stats.Error,
}

// moduleSpec represents the setting of the -vmodule flag.
type moduleSpec struct {
	filter []modulePat
}

// modulePat contains a filter for the -vmodule flag.
// It holds a verbosity level and a file pattern to match.
type modulePat struct {
	pattern string
	literal bool // The pattern is a literal string
	level   severity
}

// match reports whether the file matches the pattern. It uses a string
// comparison if the pattern contains no metacharacters.
func (m *modulePat) match(file string) bool {
	fname := filenameOnly(file)
	if m.literal {
		return fname == m.pattern
	}
	match, _ := filepath.Match(m.pattern, fname)
	/*
		if match {
			fmt.Printf("<%s> vs <%s> matched: true\n", m.pattern, fname)
		} else {
			fmt.Printf("<%s> vs <%s> matched: false\n", m.pattern, fname)
		}
	*/
	return match
}

func (m *moduleSpec) String() string {
	// Lock because the type is not atomic. TODO: clean this up.
	logging.mu.Lock()
	defer logging.mu.Unlock()
	var b bytes.Buffer
	for i, f := range m.filter {
		if i > 0 {
			b.WriteRune(',')
		}
		fmt.Fprintf(&b, "%s:%s", f.pattern, f.level.String())
	}
	return b.String()
}

// Get is part of the (Go 1.2)  flag.Getter interface. It always returns nil for this flag type since the
// struct is not exported.
func (m *moduleSpec) Get() interface{} {
	return nil
}

var errVmoduleSyntax = errors.New("syntax error: expect comma-separated list of filename=N")

// Syntax: -vmodule=recordio:debug,file:info,gfs*:warn
func (m *moduleSpec) Set(value string) error {
	m.filter = nil
	for _, pat := range strings.Split(value, ",") {
		if len(pat) == 0 {
			// Empty strings such as from a trailing comma can be ignored.
			continue
		}
		patLev := strings.Split(pat, ":")
		if len(patLev) != 2 || len(patLev[0]) == 0 || len(patLev[1]) == 0 {
			return errVmoduleSyntax
		}
		pattern := filenameOnly(patLev[0])
		v, err := severityByName(patLev[1])
		if err != nil {
			return err
		}
		// TODO: check syntax of filter?
		m.filter = append(m.filter, modulePat{pattern, isLiteral(pattern), severity(v)})
	}
	/*
		logging.mu.Lock()
		defer logging.mu.Unlock()
		logging.setVState(m.filter)
	*/
	return nil
}

// isLiteral reports whether the pattern is a literal string, that is, has no metacharacters
// that require filepath.Match to be called to match the pattern.
func isLiteral(pattern string) bool {
	return !strings.ContainsAny(pattern, `\*?[]`)
}

// traceLocation represents the setting of the -log_backtrace_at flag.
type traceLocation struct {
	file string
	line int
}

// isSet reports whether the trace location has been specified.
// logging.mu is held.
func (t *traceLocation) isSet() bool {
	return t.line > 0
}

// match reports whether the specified file and line matches the trace location.
// The argument file name is the full path, not the basename specified in the flag.
// logging.mu is held.
func (t *traceLocation) match(file string, line int) bool {
	if t.line != line {
		return false
	}
	file = filenameOnly(file)
	return t.file == file
}

func (t *traceLocation) String() string {
	// Lock because the type is not atomic. TODO: clean this up.
	logging.mu.Lock()
	defer logging.mu.Unlock()
	return fmt.Sprintf("%s:%d", t.file, t.line)
}

// Get is part of the (Go 1.2) flag.Getter interface. It always returns nil for this flag type since the
// struct is not exported
func (t *traceLocation) Get() interface{} {
	return nil
}

var errTraceSyntax = errors.New("syntax error: expect file.go:234")

// Syntax: -log_backtrace_at=gopherflakes.go:234
// Note that unlike vmodule the file extension is included here.
func (t *traceLocation) Set(value string) error {
	if value == "" {
		// Unset.
		t.line = 0
		t.file = ""
		return nil
	}
	fields := strings.Split(value, ":")
	if len(fields) != 2 {
		return errTraceSyntax
	}
	file, line := fields[0], fields[1]
	v, err := strconv.Atoi(line)
	if err != nil {
		return errTraceSyntax
	}
	if v <= 0 {
		return errors.New("negative or zero value for level")
	}
	logging.mu.Lock()
	defer logging.mu.Unlock()
	t.line = v
	t.file = filenameOnly(file)
	return nil
}

// flushSyncWriter is the interface satisfied by logging destinations.
type flushSyncWriter interface {
	Flush() error
	Sync() error
	io.Writer
}

func init() {
	flag.BoolVar(&logging.log_daily, "log_daily", true, "weather to handle log files daily")
	flag.Var(&logging.toFlag, "log_to", "log to stderr or file or both")
	flag.Var(&logging.verbosity, "v", "log level for V logs")
	flag.Var(&logging.vmodule, "vm", "comma-separated list of pattern:severity settings for file-filtered logging")
	flag.Var(&logging.traceLocation, "log_backtrace_at", "when logging hits line file:line, emit a stack trace")
	flag.IntVar(&flushInterval, "log_flush", 30, "interval time in seconds periodically flushes the log file buffers.")

	// Default
	logging.log_daily = true
	logging.verbosity = DEBUG
	logging.toFlag = Log2File

	logging.setVState(nil)
	go logging.flushDaemon()
}

// loggingT collects all the global state of the logging setup.
type loggingT struct {
	log_daily bool
	toFlag    outputFlag // -log_to flag. Handled atomically.
	verbosity severity   // -v flag. logging level, Handled atomically.

	// freeList is a list of byte buffers, maintained under freeListMu.
	freeList *buffer
	// freeListMu maintains the free list. It is separate from the main mutex
	// so buffers can be grabbed and printed to without holding the main lock,
	// for better parallelization.
	freeListMu sync.Mutex

	// mu protects the remaining elements of this structure and is
	// used to synchronize logging.
	mu sync.Mutex
	// file holds writer for each of the log types.
	file flushSyncWriter
	// traceLocation is the state of the -log_backtrace_at flag.
	traceLocation traceLocation
	// These flags are modified only under lock, although verbosity may be fetched
	// safely using atomic.LoadInt32.
	vmodule moduleSpec // The state of the -vmodule flag.
}

// buffer holds a byte Buffer for reuse. The zero value is ready for use.
type buffer struct {
	bytes.Buffer
	tmp  [64]byte // temporary byte array for creating headers.
	next *buffer
}

var logging loggingT

// setVState sets a consistent state for V logging.
// l.mu is held.
func (l *loggingT) setVState(filter []modulePat) {

	// Set the new filters and wipe the pc->Level map if the filter has changed.
	logging.vmodule.filter = filter
}

// getBuffer returns a new, ready-to-use buffer.
func (l *loggingT) getBuffer() *buffer {
	l.freeListMu.Lock()
	b := l.freeList
	if b != nil {
		l.freeList = b.next
	}
	l.freeListMu.Unlock()
	if b == nil {
		b = new(buffer)
	} else {
		b.next = nil
		b.Reset()
	}
	return b
}

// putBuffer returns a buffer to the free list.
func (l *loggingT) putBuffer(b *buffer) {
	if b.Len() >= 256 {
		// Let big buffers die a natural death.
		return
	}
	l.freeListMu.Lock()
	b.next = l.freeList
	l.freeList = b
	l.freeListMu.Unlock()
}

var timeNow = time.Now // Stubbed out for testing.

/*
header formats a log header as defined by the C++ implementation.
It returns a buffer containing the formatted header and the user's file and line number.
The depth specifies how many stack frames above lives the source line to be identified in the log message.

Log lines have this form:
	mmdd hh:mm:ss.uuuuuu threadid file:line[xxxxx] msg...
where the fields are defined as follows:
	mm               The month (zero padded; ie May is '05')
	dd               The day (zero padded)
	hh:mm:ss.uuuuuu  Time in hours, minutes and fractional seconds
	threadid         The space-padded(8 characters) thread ID as returned by GetTID()
	file             The file name
	line             The line number
	xxxxx            "DEBUG"," INFO"," WARN","ERROR","FATAL"
	msg              The user-supplied message
*/

func (l *loggingT) header(s severity, depth int) (*buffer, string, int) {
	matched := false
	_, file, line, ok := runtime.Caller(3 + depth)
	if !ok {
		file = "???"
		line = 1
	} else {
		file = filepath.Base(file)
		if len(l.vmodule.filter) > 0 {
			// check whether 'severity' or file:line should be logged
			for _, filter := range l.vmodule.filter {
				if filter.match(file) {
					matched = true
					if s < filter.level {
						return nil, file, line
					}
				}
			}
		}
	}
	if !matched && s < l.verbosity {
		return nil, file, line
	}
	return l.formatHeader(s, file, line), file, line
}

// formatHeader formats a log header using the provided file name and line number.
func (l *loggingT) formatHeader(s severity, file string, line int) *buffer {
	now := timeNow()
	if line < 0 {
		line = 0 // not a real line number, but acceptable to someDigits
	}
	if s > FATAL {
		s = INFO // for safety.
	}
	buf := l.getBuffer()

	// mmdd hh:mm:ss.uuuuuu threadid file:line[WARN]
	str := fmt.Sprintf("%02d%02d %02d:%02d:%02d.%06d%8d %s:%d[%5s] ",
		now.Month(),
		now.Day(),
		now.Hour(),
		now.Minute(),
		now.Second(),
		now.Nanosecond()/1000,
		pid, // TODO: should be TID
		file,
		line,
		s.String())
	buf.Write([]byte(str))
	return buf
}

func (l *loggingT) println(s severity, args ...interface{}) {
	buf, file, line := l.header(s, 0)
	if buf == nil {
		return
	}
	fmt.Fprintln(buf, args...)
	l.output(s, buf, file, line)
}

func (l *loggingT) print(s severity, args ...interface{}) {
	l.printDepth(s, 1, args...)
}

func (l *loggingT) printDepth(s severity, depth int, args ...interface{}) {
	buf, file, line := l.header(s, depth)
	if buf == nil {
		return
	}
	fmt.Fprint(buf, args...)
	if buf.Bytes()[buf.Len()-1] != '\n' {
		buf.WriteByte('\n')
	}
	l.output(s, buf, file, line)
}

func (l *loggingT) printf(s severity, format string, args ...interface{}) {
	buf, file, line := l.header(s, 0)
	if buf == nil {
		return
	}
	fmt.Fprintf(buf, format, args...)
	if buf.Bytes()[buf.Len()-1] != '\n' {
		buf.WriteByte('\n')
	}
	l.output(s, buf, file, line)
}

// output writes the data to the log files and releases the buffer.
func (l *loggingT) output(s severity, buf *buffer, file string, line int) {
	l.mu.Lock()
	if l.traceLocation.isSet() {
		if l.traceLocation.match(file, line) {
			buf.Write(stacks(false))
		}
	}
	data := buf.Bytes()
	if !flag.Parsed() {
		os.Stderr.Write([]byte("ERROR: logging before flag.Parse: "))
		os.Stderr.Write(data)
	} else if (l.toFlag & Log2Std) != 0 {
		os.Stderr.Write(data)
	} else if (l.toFlag & Log2File) != 0 {
		if l.file == nil {
			if err := l.createFiles(); err != nil {
				os.Stderr.Write(data) // Make sure the message appears somewhere.
				l.exit(err)
			}
		}
		l.file.Write(data)
	}
	if s == FATAL {
		// If we got here via Exit rather than Fatal, print no stacks.
		if atomic.LoadUint32(&fatalNoStacks) > 0 {
			l.mu.Unlock()
			timeoutFlush(10 * time.Second)
			os.Exit(1)
		}
		// Dump all goroutine stacks before exiting.
		// First, make sure we see the trace for the current goroutine on standard error.
		// If -logtostderr has been specified, the loop below will do that anyway
		// as the first stack in the full dump.
		if (l.toFlag & Log2Std) == 0 {
			os.Stderr.Write(stacks(false))
		}
		// Write the stack trace for all goroutines to the files.
		trace := stacks(true)
		logExitFunc = func(error) {} // If we get a write error, we'll still exit below.
		l.file.Write(trace)
		l.mu.Unlock()
		timeoutFlush(10 * time.Second)
		os.Exit(255) // C++ uses -1, which is silly because it's anded with 255 anyway.
	}
	l.putBuffer(buf)
	l.mu.Unlock()
	if stats := severityStats[s]; stats != nil {
		atomic.AddInt64(&stats.lines, 1)
		atomic.AddInt64(&stats.bytes, int64(len(data)))
	}
}

// timeoutFlush calls Flush and returns when it completes or after timeout
// elapses, whichever happens first.  This is needed because the hooks invoked
// by Flush may deadlock when glog.Fatal is called from a hook that holds
// a lock.
func timeoutFlush(timeout time.Duration) {
	done := make(chan bool, 1)
	go func() {
		Flush() // calls logging.lockAndFlushAll()
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		fmt.Fprintln(os.Stderr, "glog: Flush took longer than", timeout)
	}
}

// stacks is a wrapper for runtime.Stack that attempts to recover the data for all goroutines.
func stacks(all bool) []byte {
	// We don't know how big the traces are, so grow a few times if they don't fit. Start large, though.
	n := 10000
	if all {
		n = 100000
	}
	var trace []byte
	for i := 0; i < 5; i++ {
		trace = make([]byte, n)
		nbytes := runtime.Stack(trace, all)
		if nbytes < len(trace) {
			return trace[:nbytes]
		}
		n *= 2
	}
	return trace
}

// logExitFunc provides a simple mechanism to override the default behavior
// of exiting on error. Used in testing and to guarantee we reach a required exit
// for fatal logs. Instead, exit could be a function rather than a method but that
// would make its use clumsier.
var logExitFunc func(error)

// exit is called if there is trouble creating or writing log files.
// It flushes the logs and exits the program; there's no point in hanging around.
// l.mu is held.
func (l *loggingT) exit(err error) {
	fmt.Fprintf(os.Stderr, "log: exiting because of error: %s\n", err)
	// If logExitFunc is set, we do that instead of exiting.
	if logExitFunc != nil {
		logExitFunc(err)
		return
	}
	l.flushAll()
	os.Exit(2)
}

// syncBuffer joins a bufio.Writer to its underlying file, providing access to the
// file's Sync method and providing a wrapper for the Write method that provides log
// file rotation. There are conflicting methods, so the file cannot be embedded.
// l.mu is held for all its methods.
type syncBuffer struct {
	logger *loggingT
	*bufio.Writer
	file     *os.File
	nbytes   uint64 // The number of bytes written to this file
	createAt string
}

func (sb *syncBuffer) Sync() error {
	return sb.file.Sync()
}

func (sb *syncBuffer) Write(p []byte) (n int, err error) {
	if sb.logger.log_daily {
		if strings.Compare(sb.createAt, string(p[0:4])) == 0 {
			if err := sb.rotateFile(time.Now()); err != nil {
				sb.logger.exit(err)
			}
		}
	} else if sb.nbytes+uint64(len(p)) >= MaxSize*MB {
		if err := sb.rotateFile(time.Now()); err != nil {
			sb.logger.exit(err)
		}
	}
	n, err = sb.Writer.Write(p)
	sb.nbytes += uint64(n)
	if err != nil {
		sb.logger.exit(err)
	}
	return
}

// rotateFile closes the syncBuffer's file and starts a new one.
func (sb *syncBuffer) rotateFile(now time.Time) error {
	if sb.file != nil {
		sb.Flush()
		sb.file.Close()
	}
	var err error
	sb.file, _, err = create(now)
	sb.nbytes = 0
	if err != nil {
		return err
	}

	sb.Writer = bufio.NewWriterSize(sb.file, bufferSize)
	sb.createAt = fmt.Sprintf("%02d%02d", now.Month(), now.Day())

	// Write header.
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Log file created at: %s\n", now.Format("2006/01/02 15:04:05"))
	fmt.Fprintf(&buf, "Running on machine: %s\n", host)
	fmt.Fprintf(&buf, "Binary: Built with %s %s for %s/%s\n", runtime.Compiler, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(&buf, "Log line format: mmdd hh:mm:ss.uuuuuu threadid file:line[IWEF] msg\n")
	n, err := sb.file.Write(buf.Bytes())
	sb.nbytes += uint64(n)
	return err
}

// bufferSize sizes the buffer associated with each log file. It's large
// so that log records can accumulate without the logging thread blocking
// on disk I/O. The flushDaemon will block instead.
const bufferSize = 256 * 1024

// createFiles creates all the log files for severity from sev down to INFO.
// l.mu is held.
func (l *loggingT) createFiles() error {
	now := time.Now()
	sb := &syncBuffer{
		logger: l,
	}
	if err := sb.rotateFile(now); err != nil {
		return err
	}
	l.file = sb
	return nil
}

var flushInterval int = 30

// flushDaemon periodically flushes the log file buffers.
func (l *loggingT) flushDaemon() {
	for _ = range time.NewTicker(time.Duration(flushInterval) * time.Second).C {
		l.lockAndFlushAll()
	}
}

// lockAndFlushAll is like flushAll but locks l.mu first.
func (l *loggingT) lockAndFlushAll() {
	l.mu.Lock()
	l.flushAll()
	l.mu.Unlock()
}

// flushAll flushes all the logs and attempts to "sync" their data to disk.
// l.mu is held.
func (l *loggingT) flushAll() {
	// Flush from fatal down, in case there's trouble flushing.
	if l.file != nil {
		l.file.Flush() // ignore error
		l.file.Sync()  // ignore error
	}
}

// Get file name only, without path and suffix
func filenameOnly(fullFilename string) string {
	filenameWithSuffix := filepath.Base(fullFilename)
	fileSuffix := filepath.Ext(filenameWithSuffix)

	return strings.TrimSuffix(filenameWithSuffix, fileSuffix)
}

// Debug logs to the DEBUG log.
// Arguments are handled in the manner of fmt.Print; a newline is appended if missing.
func Debug(args ...interface{}) {
	logging.print(DEBUG, args...)
}

// DebugDepth acts as Debug but uses depth to determine which call frame to log.
// DebugDepth(0, "msg") is the same as Debug("msg").
func DebugDepth(depth int, args ...interface{}) {
	logging.printDepth(DEBUG, depth, args...)
}

// Debugln logs to the DEBUG log.
// Arguments are handled in the manner of fmt.Println; a newline is appended if missing.
func Debugln(args ...interface{}) {
	logging.println(DEBUG, args...)
}

// Debugf logs to the DEBUG log.
// Arguments are handled in the manner of fmt.Printf; a newline is appended if missing.
func Debugf(format string, args ...interface{}) {
	logging.printf(DEBUG, format, args...)
}

// Info logs to the INFO log.
// Arguments are handled in the manner of fmt.Print; a newline is appended if missing.
func Info(args ...interface{}) {
	logging.print(INFO, args...)
}

// InfoDepth acts as Info but uses depth to determine which call frame to log.
// InfoDepth(0, "msg") is the same as Info("msg").
func InfoDepth(depth int, args ...interface{}) {
	logging.printDepth(INFO, depth, args...)
}

// Infoln logs to the INFO log.
// Arguments are handled in the manner of fmt.Println; a newline is appended if missing.
func Infoln(args ...interface{}) {
	logging.println(INFO, args...)
}

// Infof logs to the INFO log.
// Arguments are handled in the manner of fmt.Printf; a newline is appended if missing.
func Infof(format string, args ...interface{}) {
	logging.printf(INFO, format, args...)
}

// Warning logs to the WARNING and INFO logs.
// Arguments are handled in the manner of fmt.Print; a newline is appended if missing.
func Warn(args ...interface{}) {
	logging.print(WARN, args...)
}

// WarningDepth acts as Warning but uses depth to determine which call frame to log.
// WarningDepth(0, "msg") is the same as Warning("msg").
func WarnDepth(depth int, args ...interface{}) {
	logging.printDepth(WARN, depth, args...)
}

// Warningln logs to the WARNING and INFO logs.
// Arguments are handled in the manner of fmt.Println; a newline is appended if missing.
func Warnln(args ...interface{}) {
	logging.println(WARN, args...)
}

// Warningf logs to the WARNING and INFO logs.
// Arguments are handled in the manner of fmt.Printf; a newline is appended if missing.
func Warnf(format string, args ...interface{}) {
	logging.printf(WARN, format, args...)
}

// Error logs to the ERROR, WARNING, and INFO logs.
// Arguments are handled in the manner of fmt.Print; a newline is appended if missing.
func Error(args ...interface{}) {
	logging.print(ERROR, args...)
}

// ErrorDepth acts as Error but uses depth to determine which call frame to log.
// ErrorDepth(0, "msg") is the same as Error("msg").
func ErrorDepth(depth int, args ...interface{}) {
	logging.printDepth(ERROR, depth, args...)
}

// Errorln logs to the ERROR, WARNING, and INFO logs.
// Arguments are handled in the manner of fmt.Println; a newline is appended if missing.
func Errorln(args ...interface{}) {
	logging.println(ERROR, args...)
}

// Errorf logs to the ERROR, WARNING, and INFO logs.
// Arguments are handled in the manner of fmt.Printf; a newline is appended if missing.
func Errorf(format string, args ...interface{}) {
	logging.printf(ERROR, format, args...)
}

// Fatal logs to the FATAL, ERROR, WARNING, and INFO logs,
// including a stack trace of all running goroutines, then calls os.Exit(255).
// Arguments are handled in the manner of fmt.Print; a newline is appended if missing.
func Fatal(args ...interface{}) {
	logging.print(FATAL, args...)
}

// FatalDepth acts as Fatal but uses depth to determine which call frame to log.
// FatalDepth(0, "msg") is the same as Fatal("msg").
func FatalDepth(depth int, args ...interface{}) {
	logging.printDepth(FATAL, depth, args...)
}

// Fatalln logs to the FATAL, ERROR, WARNING, and INFO logs,
// including a stack trace of all running goroutines, then calls os.Exit(255).
// Arguments are handled in the manner of fmt.Println; a newline is appended if missing.
func Fatalln(args ...interface{}) {
	logging.println(FATAL, args...)
}

// Fatalf logs to the FATAL, ERROR, WARNING, and INFO logs,
// including a stack trace of all running goroutines, then calls os.Exit(255).
// Arguments are handled in the manner of fmt.Printf; a newline is appended if missing.
func Fatalf(format string, args ...interface{}) {
	logging.printf(FATAL, format, args...)
}

// fatalNoStacks is non-zero if we are to exit without dumping goroutine stacks.
// It allows Exit and relatives to use the Fatal logs.
var fatalNoStacks uint32

// Exit logs to the FATAL, ERROR, WARNING, and INFO logs, then calls os.Exit(1).
// Arguments are handled in the manner of fmt.Print; a newline is appended if missing.
func Exit(args ...interface{}) {
	atomic.StoreUint32(&fatalNoStacks, 1)
	logging.print(FATAL, args...)
}

// ExitDepth acts as Exit but uses depth to determine which call frame to log.
// ExitDepth(0, "msg") is the same as Exit("msg").
func ExitDepth(depth int, args ...interface{}) {
	atomic.StoreUint32(&fatalNoStacks, 1)
	logging.printDepth(FATAL, depth, args...)
}

// Exitln logs to the FATAL, ERROR, WARNING, and INFO logs, then calls os.Exit(1).
func Exitln(args ...interface{}) {
	atomic.StoreUint32(&fatalNoStacks, 1)
	logging.println(FATAL, args...)
}

// Exitf logs to the FATAL, ERROR, WARNING, and INFO logs, then calls os.Exit(1).
// Arguments are handled in the manner of fmt.Printf; a newline is appended if missing.
func Exitf(format string, args ...interface{}) {
	atomic.StoreUint32(&fatalNoStacks, 1)
	logging.printf(FATAL, format, args...)
}

func (l *loggingT) setVerosity(s severity) error {
	if s >= DEBUG && s < numSeverity {
		l.verbosity = s
		return nil
	}
	return errSeveritySyntax
}

// (DEBUG/INFO/WARN/ERROR/FATAL)
func V(s severity) error {
	logging.mu.Lock()
	defer logging.mu.Unlock()
	return logging.setVerosity(s)
}

// (Log2Std|Log2File|LogDailyRolling)
func SetFlags(f int) error {
	logging.mu.Lock()
	defer logging.mu.Unlock()
	ff := outputFlag(f)
	logging.toFlag = (ff & (Log2File | Log2Std))
	if (ff & LogDailyRolling) != 0 {
		logging.log_daily = true
	} else {
		logging.log_daily = false
	}
	return nil
}

func SetMaxSize(max int) {
	logging.mu.Lock()
	defer logging.mu.Unlock()
	MaxSize = (uint64)(max)
}

// file1.go:debug,file2.go:info
func Vmodule(v string) error {
	logging.mu.Lock()
	defer logging.mu.Unlock()
	return logging.vmodule.Set(v)
}

// xxx.go:120
func Vbacktrace(v string) error {
	logging.mu.Lock()
	defer logging.mu.Unlock()
	return logging.traceLocation.Set(v)
}

// Flush flushes all pending log I/O.
func Flush() {
	logging.lockAndFlushAll()
}
