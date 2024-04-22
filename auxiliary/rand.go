package auxiliary

import (
	"math/rand"
	"sync"
)

var (
	mu sync.Mutex
)

// Generate random number with Asynchronous Protect
func GenRand(n int, r *rand.Rand) int {
	mu.Lock()
	res := r.Intn(n)
	mu.Unlock()
	return res
}
