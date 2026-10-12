package main

import (
	"secweaver-agent/pkg/eventwhitelist"
	"sync/atomic"
)

// The supervised process owns this optional controller. Module children have
// their own readers and never access the parent's pointer or policy-write lock.
var collectionController atomic.Pointer[eventwhitelist.Controller]
