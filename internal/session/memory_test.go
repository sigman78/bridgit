package session

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"
)

func boundTransaction(expiresAt time.Time) Transaction {
	return Transaction{BindingHash: sha256.Sum256([]byte("browser-binding")), ExpiresAt: expiresAt}
}

func TestMemoryBoundsPendingTransactionsAndReclaimsExpiredEntries(t *testing.T) {
	now := time.Now()
	store := NewMemory(func() time.Time { return now })
	for index := 0; index < MaxPendingTransactions; index++ {
		if err := store.PutTransaction(fmt.Sprintf("state-%d", index), boundTransaction(now.Add(time.Minute))); err != nil {
			t.Fatalf("PutTransaction(%d) error = %v", index, err)
		}
	}
	if err := store.PutTransaction("over-capacity", boundTransaction(now.Add(time.Minute))); err == nil {
		t.Fatal("PutTransaction succeeded over the pending transaction limit")
	}

	now = now.Add(2 * time.Minute)
	if err := store.PutTransaction("after-expiry", boundTransaction(now.Add(time.Minute))); err != nil {
		t.Fatalf("PutTransaction did not reclaim expired entries: %v", err)
	}
}

func TestPutTransactionRequiresABrowserBinding(t *testing.T) {
	now := time.Now()
	store := NewMemory(func() time.Time { return now })
	if err := store.PutTransaction("unbound", Transaction{ExpiresAt: now.Add(time.Minute)}); err == nil {
		t.Fatal("PutTransaction accepted a transaction with no browser binding")
	}
	if _, err := store.TakeTransaction("unbound"); err == nil {
		t.Fatal("an unbound transaction was stored despite the error")
	}
}
