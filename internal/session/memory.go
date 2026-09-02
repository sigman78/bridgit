package session

import (
	"errors"
	"sync"
	"time"

	"github.com/sigman78/bridgit/internal/identity"
)

const (
	// MaxPendingTransactions bounds unauthenticated browser state.
	MaxPendingTransactions = 1024
	maxBridgeSessions      = 4096
	maxSAMLRequestIDs      = 8192
)

// Transaction is a single-use continuation between SAML and OIDC.
type Transaction struct {
	ReturnURL    string
	Nonce        string
	PKCEVerifier string
	ExpiresAt    time.Time
}

// BridgeSession is a server-side reference to a verified principal.
type BridgeSession struct {
	Principal identity.Principal
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Memory stores bounded-lifetime browser state for a single Bridgit process.
type Memory struct {
	mu           sync.Mutex
	now          func() time.Time
	transactions map[string]Transaction
	sessions     map[string]BridgeSession
	samlRequests map[string]time.Time
}

// NewMemory creates an empty in-process state store.
func NewMemory(now func() time.Time) *Memory {
	if now == nil {
		now = time.Now
	}
	return &Memory{
		now:          now,
		transactions: make(map[string]Transaction),
		sessions:     make(map[string]BridgeSession),
		samlRequests: make(map[string]time.Time),
	}
}

// UseSAMLRequest records an authentication request ID once for its replay
// window. It returns false when that ID was already used or is empty.
func (m *Memory) UseSAMLRequest(id string, expiresAt time.Time) bool {
	if id == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for requestID, expiry := range m.samlRequests {
		if !expiry.After(now) {
			delete(m.samlRequests, requestID)
		}
	}
	if _, exists := m.samlRequests[id]; exists {
		return false
	}
	if len(m.samlRequests) >= maxSAMLRequestIDs {
		return false
	}
	m.samlRequests[id] = expiresAt
	return true
}

// TakeTransaction atomically consumes one unexpired authorization transaction.
func (m *Memory) TakeTransaction(state string) (Transaction, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeExpiredTransactionsLocked()
	transaction, ok := m.transactions[state]
	if !ok {
		return Transaction{}, errors.New("authorization transaction was not found or has expired")
	}
	delete(m.transactions, state)
	return transaction, nil
}

// PutSession records a verified principal under an opaque browser identifier.
func (m *Memory) PutSession(id string, bridgeSession BridgeSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeExpiredSessionsLocked()
	if id == "" || !bridgeSession.ExpiresAt.After(m.now()) {
		return errors.New("session ID and future expiry are required")
	}
	if _, exists := m.sessions[id]; !exists && len(m.sessions) >= maxBridgeSessions {
		return errors.New("bridge session capacity reached")
	}
	m.sessions[id] = bridgeSession
	return nil
}

// GetSession returns one unexpired server-side browser session.
func (m *Memory) GetSession(id string) (BridgeSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeExpiredSessionsLocked()
	bridgeSession, ok := m.sessions[id]
	return bridgeSession, ok
}

// DeleteSession invalidates one local browser session.
func (m *Memory) DeleteSession(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
}

// PutTransaction records a transaction under its unpredictable OAuth state.
func (m *Memory) PutTransaction(state string, transaction Transaction) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeExpiredTransactionsLocked()
	if state == "" || !transaction.ExpiresAt.After(m.now()) {
		return errors.New("transaction state and future expiry are required")
	}
	if _, exists := m.transactions[state]; !exists && len(m.transactions) >= MaxPendingTransactions {
		return errors.New("pending transaction capacity reached")
	}
	m.transactions[state] = transaction
	return nil
}

func (m *Memory) removeExpiredSessionsLocked() {
	now := m.now()
	for id, bridgeSession := range m.sessions {
		if !bridgeSession.ExpiresAt.After(now) {
			delete(m.sessions, id)
		}
	}
}

func (m *Memory) removeExpiredTransactionsLocked() {
	now := m.now()
	for state, transaction := range m.transactions {
		if !transaction.ExpiresAt.After(now) {
			delete(m.transactions, state)
		}
	}
}
