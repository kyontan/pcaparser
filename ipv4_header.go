package pcaparser

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
)

const (
	Version          = 4  // protocol version
	IPv4HeaderLen    = 20 // header length without extension headers
	maxIPv4HeaderLen = 60 // sensible default, revisit if later RFCs define new usage of version and header length fields
)

var (
	errIPv4HeaderTooShort = errors.New("header too short")
	errBufferTooShort     = errors.New("buffer too short")

	// See http://www.freebsd.org/doc/en/books/porters-handbook/freebsd-versions.html.
	freebsdVersion uint32

	// nativeEndian binary.ByteOrder
)

type IPv4HeaderFlags int

const (
	MoreFragments IPv4HeaderFlags = 1 << iota // more fragments flag
	DontFragment                              // don't fragment flag
)

//IPv4Protocol
type IPv4Protocol uint8

const (
	IP_ICMPType      IPv4Protocol = 1
	IP_IGMPType      IPv4Protocol = 2
	IP_IPType        IPv4Protocol = 4
	IP_TCPType       IPv4Protocol = 6
	IP_CBTType       IPv4Protocol = 7
	IP_EGPType       IPv4Protocol = 8
	IP_IGPType       IPv4Protocol = 9
	IP_UDPType       IPv4Protocol = 17
	IP_IPv6Type      IPv4Protocol = 41
	IP_IDRPType      IPv4Protocol = 45
	IP_RSVPType      IPv4Protocol = 46
	IP_GREType       IPv4Protocol = 47
	IP_ESPType       IPv4Protocol = 50
	IP_AHType        IPv4Protocol = 51
	IP_MOBILEType    IPv4Protocol = 55
	IP_EIGRPType     IPv4Protocol = 88
	IP_OSPFType      IPv4Protocol = 89
	IP_IPIPType      IPv4Protocol = 94
	IP_PIMType       IPv4Protocol = 103
	IP_VRRPType      IPv4Protocol = 112
	IP_PGMType       IPv4Protocol = 113
	IP_L2TPType      IPv4Protocol = 115
	IP_IPv6ICMPType  IPv4Protocol = 58
	IP_IPv6RouteType IPv4Protocol = 43
	IP_IPv6FragType  IPv4Protocol = 44
	IP_IPv6NoNxtType IPv4Protocol = 59
	IP_IPv6OptsType  IPv4Protocol = 60
)

// A Header represents an IPv4 header.
type IPv4Header struct {
	Version  int             // protocol version
	Len      int             // header length
	TOS      int             // type-of-service
	TotalLen int             // packet total length
	ID       int             // identification
	Flags    IPv4HeaderFlags // flags
	FragOff  int             // fragment offset
	TTL      int             // time-to-live
	Protocol IPv4Protocol    // next protocol
	Checksum int             // checksum
	Src      net.IP          // source address
	Dst      net.IP          // destination address
	Options  []byte          // options, extension headers
}

func (h *IPv4Header) String() string {
	if h == nil {
		return "<nil>"
	}
	return fmt.Sprintf("ver=%d hdrlen=%d tos=%#x totallen=%d id=%#x flags=%#x fragoff=%#x ttl=%d proto=%d cksum=%#x src=%v dst=%v", h.Version, h.Len, h.TOS, h.TotalLen, h.ID, h.Flags, h.FragOff, h.TTL, h.Protocol, h.Checksum, h.Src, h.Dst)
}

// ParseIPv4Header parses b as an IPv4 header.
func ParseIPv4Header(b []byte) (*IPv4Header, error) {
	if len(b) < IPv4HeaderLen {
		return nil, errIPv4HeaderTooShort
	}
	hdrlen := int(b[0]&0x0f) << 2
	if hdrlen > len(b) {
		return nil, errBufferTooShort
	}
	h := &IPv4Header{
		Version:  int(b[0] >> 4),
		Len:      hdrlen,
		TOS:      int(b[1]),
		ID:       int(binary.BigEndian.Uint16(b[4:6])),
		TTL:      int(b[8]),
		Protocol: IPv4Protocol(b[9]),
		Checksum: int(binary.BigEndian.Uint16(b[10:12])),
		Src:      net.IPv4(b[12], b[13], b[14], b[15]),
		Dst:      net.IPv4(b[16], b[17], b[18], b[19]),
	}
	switch runtime.GOOS {
	case "darwin", "dragonfly", "netbsd":
		h.TotalLen = int(binary.BigEndian.Uint16(b[2:4])) + hdrlen
		h.FragOff = int(binary.BigEndian.Uint16(b[6:8]))
	case "freebsd":
		if freebsdVersion < 1100000 {
			h.TotalLen = int(binary.BigEndian.Uint16(b[2:4]))
			if freebsdVersion < 1000000 {
				h.TotalLen += hdrlen
			}
			h.FragOff = int(binary.BigEndian.Uint16(b[6:8]))
		} else {
			h.TotalLen = int(binary.BigEndian.Uint16(b[2:4]))
			h.FragOff = int(binary.BigEndian.Uint16(b[6:8]))
		}
	default:
		h.TotalLen = int(binary.BigEndian.Uint16(b[2:4]))
		h.FragOff = int(binary.BigEndian.Uint16(b[6:8]))
	}
	h.Flags = IPv4HeaderFlags(h.FragOff&0xe000) >> 13
	h.FragOff = h.FragOff & 0x1fff
	if hdrlen-IPv4HeaderLen > 0 {
		h.Options = make([]byte, hdrlen-IPv4HeaderLen)
		copy(h.Options, b[IPv4HeaderLen:])
	}
	return h, nil
}

//String
func (e IPv4Protocol) String() string {
	var out string
	// log.Println(uint16(e), uint16(E_IPv4Type))
	switch e {
	case IP_ICMPType:
		out = "ICMP" // "Internet Control Message"
		break
	case IP_IGMPType:
		out = "IGMP" // "Internet Group Management"
		break
	case IP_IPType:
		out = "IP" // "IP in IP"
		break
	case IP_TCPType:
		out = "TCP" // "Transmission Control"
		break
	case IP_CBTType:
		out = "CBT" // "CBT"
		break
	case IP_EGPType:
		out = "EGP" // "Exterior Gateway Protocol"
		break
	case IP_IGPType:
		out = "IGP" // "Interior Gateway Protocol"
		break
	case IP_UDPType:
		out = "UDP" // "User Datagram Protocol"
		break
	case IP_IPv6Type:
		out = "IPv6" // "IPv6"
		break
	case IP_IDRPType:
		out = "IDRP" // "Inter-Domain Routing Protocol"
		break
	case IP_RSVPType:
		out = "RSVP" // "Reservation Protocol"
		break
	case IP_GREType:
		out = "GRE" // "General Routing Encapsulation"
		break
	case IP_ESPType:
		out = "ESP" // "Encap Security Payload"
		break
	case IP_AHType:
		out = "AH" // "Authentication Header"
		break
	case IP_MOBILEType:
		out = "MOBILE" // "IP Mobility"
		break
	case IP_EIGRPType:
		out = "EIGRP" // "EIGRP"
		break
	case IP_OSPFType:
		out = "OSPF" // "OSPF"
		break
	case IP_IPIPType:
		out = "IPIP" // "IP-within-IP Encapsulation Protocol"
		break
	case IP_PIMType:
		out = "PIM" // "Protocol Independent Multicast"
		break
	case IP_VRRPType:
		out = "VRRP" // "Virtual Router Redundancy Protocol"
		break
	case IP_PGMType:
		out = "PGM" // "PGM Reliable Transport Protocol"
		break
	case IP_L2TPType:
		out = "L2TP" // "Layer Two Tunneling Protocol"
		break
	case IP_IPv6ICMPType:
		out = "IPv6-ICMP" // "ICMP for IPv6"
		break
	case IP_IPv6RouteType:
		out = "IPv6-Route" // "Routing Header for IPv6"
		break
	case IP_IPv6FragType:
		out = "IPv6-Frag" // "Fragment Header for IPv6"
		break
	case IP_IPv6NoNxtType:
		out = "IPv6-NoNxt" // "No Next Header for IPv6"
		break
	case IP_IPv6OptsType:
		out = "IPv6-Opts" // "Destination Options for IPv6"
		break
	default:
		out = strconv.FormatUint(uint64(uint16(e)), 10)
	}
	return out
}

//Int
func (e IPv4Protocol) Int() int {
	return int(uint16(e))
}
