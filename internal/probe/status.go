package probe

// iphlpapi status codes (ipexport.h). They are returned in the Status field of the
// reply record, and, when there is no reply at all, as the GetLastError error code.
const (
	ipSuccess             uint32 = 0     // IP_SUCCESS: echo reply from the target
	ipBufTooSmall         uint32 = 11001 // IP_BUF_TOO_SMALL
	ipDestNetUnreachable  uint32 = 11002 // IP_DEST_NET_UNREACHABLE
	ipDestHostUnreachable uint32 = 11003 // IP_DEST_HOST_UNREACHABLE
	ipDestProtUnreachable uint32 = 11004 // IP_DEST_PROT_UNREACHABLE
	ipDestPortUnreachable uint32 = 11005 // IP_DEST_PORT_UNREACHABLE
	ipPathMTUChanged      uint32 = 11006 // IP_PATH_MTU_CHANGED (v6)
	ipReqTimedOut         uint32 = 11010 // IP_REQ_TIMED_OUT: no reply before the timeout expired
	ipBadOption           uint32 = 11011 // IP_BAD_OPTION
	ipBadDestination      uint32 = 11012 // IP_BAD_DESTINATION
	ipTTLExpiredTransit   uint32 = 11013 // IP_TTL_EXPIRED_TRANSIT: the packet died in transit (this is our hop!)
	ipUnknownHost         uint32 = 11014 // IP_UNKNOWN_HOST? (undocumented, rarely seen)
	ipProtocolUnreachable uint32 = 11015 // IP_PROTOCOL_UNREACHABLE
	ipSourceQuench        uint32 = 11016 // IP_SOURCE_QUENCH
	ipOptionTooBig        uint32 = 11017 // IP_OPTION_TOO_BIG
	ipBadHeader           uint32 = 11018 // IP_BAD_HEADER
	ipUnrecognizedAddress uint32 = 11024 // IP_UNRECOGNIZED_ADDRESS? (extension)
	ipGeneralFailure      uint32 = 11050 // IP_GENERAL_FAILURE
	ipPending             uint32 = 11099 // IP_PENDING
)

// Win32 errors that iphlpapi may return instead of an ICMP status.
const (
	winErrorNetworkUnreachable uint32 = 1231 // "The network location cannot be reached."
	winErrorHostUnreachable    uint32 = 1232
)

// Kind classifies a probe result for the engine and the renderers.
type Kind int

const (
	// KindReply: an echo reply from the target itself — the route was completed.
	KindReply Kind = iota
	// KindHop: the TTL/hop limit expired in transit — an intermediate router replied.
	KindHop
	// KindTimeout: no reply (counted as packet loss).
	KindTimeout
	// KindUnreachable: ICMP Destination Unreachable (net/host/prot/port/admin prohibited).
	KindUnreachable
	// KindError: any other Windows function/stack error.
	KindError
)

func (k Kind) String() string {
	switch k {
	case KindReply:
		return "reply"
	case KindHop:
		return "hop"
	case KindTimeout:
		return "timeout"
	case KindUnreachable:
		return "unreachable"
	default:
		return "error"
	}
}

// Classify maps an iphlpapi status code to a Kind.
func Classify(status uint32) Kind {
	switch status {
	case ipSuccess:
		return KindReply
	case ipTTLExpiredTransit:
		return KindHop
	case ipReqTimedOut:
		return KindTimeout
	case ipDestNetUnreachable, ipDestHostUnreachable, ipDestProtUnreachable,
		ipDestPortUnreachable, ipProtocolUnreachable, winErrorNetworkUnreachable, winErrorHostUnreachable:
		return KindUnreachable
	default:
		return KindError
	}
}

// StatusName is the human-readable name of a code (for the "!H"/"!N" columns and JSON).
func StatusName(status uint32) string {
	switch status {
	case ipSuccess:
		return "IP_SUCCESS"
	case ipBufTooSmall:
		return "IP_BUF_TOO_SMALL"
	case ipDestNetUnreachable:
		return "IP_DEST_NET_UNREACHABLE"
	case ipDestHostUnreachable:
		return "IP_DEST_HOST_UNREACHABLE"
	case ipDestProtUnreachable:
		return "IP_DEST_PROT_UNREACHABLE"
	case ipDestPortUnreachable:
		return "IP_DEST_PORT_UNREACHABLE"
	case ipPathMTUChanged:
		return "IP_PATH_MTU_CHANGED"
	case ipReqTimedOut:
		return "IP_REQ_TIMED_OUT"
	case ipBadOption:
		return "IP_BAD_OPTION"
	case ipBadDestination:
		return "IP_BAD_DESTINATION"
	case ipTTLExpiredTransit:
		return "IP_TTL_EXPIRED_TRANSIT"
	case ipProtocolUnreachable:
		return "IP_PROTOCOL_UNREACHABLE"
	case ipSourceQuench:
		return "IP_SOURCE_QUENCH"
	case ipOptionTooBig:
		return "IP_OPTION_TOO_BIG"
	case ipBadHeader:
		return "IP_BAD_HEADER"
	case ipGeneralFailure:
		return "IP_GENERAL_FAILURE"
	case winErrorNetworkUnreachable:
		return "ERROR_NETWORK_UNREACHABLE"
	case winErrorHostUnreachable:
		return "ERROR_HOST_UNREACHABLE"
	default:
		return "UNKNOWN"
	}
}

// ShortFlag is the compact marker for the interactive table in mtr style ("!H", "!N", ...).
func ShortFlag(status uint32) string {
	switch status {
	case ipDestNetUnreachable:
		return "!N"
	case ipDestHostUnreachable, winErrorHostUnreachable:
		return "!H"
	case ipDestProtUnreachable, ipProtocolUnreachable:
		return "!P"
	case ipDestPortUnreachable:
		return "!X"
	case ipPathMTUChanged:
		return "!Q"
	case ipBadDestination:
		return "!A"
	case ipGeneralFailure, winErrorNetworkUnreachable:
		return "!?"
	default:
		return ""
	}
}
