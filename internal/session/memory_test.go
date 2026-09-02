package session

import (
	"fmt"
	"testing"
	"time"
)

func TestMemoryBoundsPendingTransactionsAndReclaimsExpiredEntries(t *testing.T) {
	now := time.Now()
	store := NewMemory(func() time.Time { return now })
	for index := 0; index < MaxPendingTransactions; index++ {
		if err := store.PutTransaction(fmt.Sprintf("state-%d", index), Transaction{ExpiresAt: now.Add(time.Minute)}); err != nil {
			t.Fatalf("PutTransaction(%d) error = %v", index, err)
		}
	}
	if err := store.PutTransaction("over-capacity", Transaction{ExpiresAt: now.Add(time.Minute)}); err == nil {
		t.Fatal("PutTransaction succeeded over the pending transaction limit")
	}

	now = now.Add(2 * time.Minute)
	if err := store.PutTransaction("after-expiry", Transaction{ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("PutTransaction did not reclaim expired entries: %v", err)
	}
}
