package behaviorlearning

import "fmt"

// Inspect reads an atomic authenticated checkpoint without taking the writer
// lock. It never creates files or resets progress while the collector is live.
func Inspect(dir string, budgetMB int) (*State, error) {
	if budgetMB < 8 || budgetMB > 256 {
		return nil, fmt.Errorf("invalid state budget")
	}
	s := &Store{dir: dir, limit: int64(budgetMB) << 20}
	key, err := s.read("key", 32)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("learning key unavailable")
	}
	s.Key = key
	state, err := s.Load()
	if err != nil {
		return nil, err
	}
	if state == nil {
		return nil, fmt.Errorf("learning has not initialized")
	}
	return state, nil
}
