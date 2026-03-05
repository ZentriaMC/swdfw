package rule

// Family represents the IP address family (IPv4 or IPv6).
type Family byte

const (
	FamilyIPv4 Family = iota
	FamilyIPv6
)
