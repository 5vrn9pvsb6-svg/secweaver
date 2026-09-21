package main

import "os"

// moduleProcessControl owns the supervisor-to-child stop channel and optional
// operating-system containment handle for one module generation.
type moduleProcessControl struct {
	requestStop func() error
	afterStart  func(*os.Process) error
	close       func()
}
