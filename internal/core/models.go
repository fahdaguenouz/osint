package core

import "time"

type Kind string

const (
	KindFullName Kind = "full-name"
	KindIP       Kind = "ip"
	KindUsername Kind = "username"
	KindDomain   Kind = "domain" // NEW: for subdomain enumeration
)

type Result struct {
	Kind      Kind
	Input     string
	Timestamp time.Time

	// Unified metadata
	Sources  []string
	Warnings []string
	Error    string // empty = success

	// Payload (only one should be filled depending on Kind)
	FullName FullNameResult
	IP       IPResult
	Username UsernameResult
	Domain   DomainResult // NEW
}

type FullNameResult struct {
	FirstName string
	LastName  string
	Address   string
	Phone     string
}

type IPResult struct {
	IP           string
	ISP          string
	City         string
	Country      string
	ASN          string
	Lat          float64
	Lon          float64
	AbuseScore   int    // 0-100 from AbuseIPDB
	AbuseReports int    // Total number of reports
	KnownIssues  string // Formatted summary
}
type UsernameResult struct {
	Username string
	Networks []NetworkResult
}

type NetworkResult struct {
	Name  string
	URL   string
	Found bool
}

// NEW: Domain result structures
type DomainResult struct {
	Domain     string
	Subdomains []SubdomainInfo
}

type SubdomainInfo struct {
	Name         string
	IP           string
	CNAME        string
	SSLValid     bool
	SSLExpiry    string
	TakeoverRisk string // "none", "potential", or specific message
}

// ---- Constructors ----

func NewBaseResult(kind Kind, input string) Result {
	return Result{
		Kind:      kind,
		Input:     input,
		Timestamp: time.Now(),
	}
}

func Fail(kind Kind, input string, err error) Result {
	r := NewBaseResult(kind, input)
	if err != nil {
		r.Error = err.Error()
	}
	return r
}