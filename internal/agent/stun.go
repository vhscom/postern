package agent

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// STUN binding request (RFC 5389): 20-byte header, no attributes.
// Type: 0x0001 (Binding Request), Length: 0, Magic: 0x2112A442, Transaction ID: 12 random bytes.

const stunMagic = 0x2112A442

var stunServers = []string{
	"stun.l.google.com:19302",
	"stun.cloudflare.com:3478",
	"stun.stunprotocol.org:3478",
}

// discoverEndpoint sends STUN binding requests to discover this host's
// public IP:port as seen from the internet. Pure Go, zero dependencies.
func discoverEndpoint(ctx context.Context, listenPort int) (string, error) {
	for _, server := range stunServers {
		ep, err := stunQuery(ctx, server, listenPort)
		if err == nil {
			return ep, nil
		}
	}
	return "", fmt.Errorf("all STUN servers failed")
}

func stunQuery(ctx context.Context, server string, listenPort int) (string, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(3 * time.Second)
	} else if time.Until(deadline) > 3*time.Second {
		deadline = time.Now().Add(3 * time.Second)
	}

	laddr := &net.UDPAddr{Port: listenPort}
	raddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return "", err
	}

	conn, err := net.DialUDP("udp4", laddr, raddr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(deadline)

	// Build STUN Binding Request
	var txID [12]byte
	// Use connection local port as part of txID for correlation
	binary.BigEndian.PutUint32(txID[0:4], uint32(listenPort))
	binary.BigEndian.PutUint64(txID[4:12], uint64(time.Now().UnixNano()))

	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], 0x0001) // Binding Request
	binary.BigEndian.PutUint16(req[2:4], 0)      // Length: 0
	binary.BigEndian.PutUint32(req[4:8], stunMagic)
	copy(req[8:20], txID[:])

	if _, err := conn.Write(req); err != nil {
		return "", err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	if n < 20 {
		return "", fmt.Errorf("STUN response too short")
	}

	return parseSTUNResponse(buf[:n], txID)
}

func parseSTUNResponse(data []byte, txID [12]byte) (string, error) {
	// Verify header
	msgType := binary.BigEndian.Uint16(data[0:2])
	if msgType != 0x0101 { // Binding Success Response
		return "", fmt.Errorf("unexpected STUN response type: 0x%04x", msgType)
	}
	magic := binary.BigEndian.Uint32(data[4:8])
	if magic != stunMagic {
		return "", fmt.Errorf("invalid STUN magic cookie")
	}

	msgLen := binary.BigEndian.Uint16(data[2:4])
	if int(msgLen)+20 > len(data) {
		return "", fmt.Errorf("STUN message length mismatch")
	}

	// Parse attributes looking for XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001)
	offset := 20
	end := 20 + int(msgLen)
	for offset+4 <= end {
		attrType := binary.BigEndian.Uint16(data[offset : offset+2])
		attrLen := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4

		if offset+int(attrLen) > end {
			break
		}

		switch attrType {
		case 0x0020: // XOR-MAPPED-ADDRESS
			return parseXORMappedAddress(data[offset : offset+int(attrLen)])
		case 0x0001: // MAPPED-ADDRESS (fallback)
			return parseMappedAddress(data[offset : offset+int(attrLen)])
		}

		// Attributes are padded to 4-byte boundaries
		offset += int(attrLen)
		if pad := attrLen % 4; pad != 0 {
			offset += int(4 - pad)
		}
	}

	return "", fmt.Errorf("no mapped address in STUN response")
}

func parseXORMappedAddress(data []byte) (string, error) {
	if len(data) < 8 {
		return "", fmt.Errorf("XOR-MAPPED-ADDRESS too short")
	}
	family := data[1]
	if family != 0x01 { // IPv4
		return "", fmt.Errorf("unsupported address family: %d", family)
	}

	xPort := binary.BigEndian.Uint16(data[2:4])
	port := xPort ^ uint16(stunMagic>>16)

	ip := make(net.IP, 4)
	magicBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(magicBytes, stunMagic)
	for i := 0; i < 4; i++ {
		ip[i] = data[4+i] ^ magicBytes[i]
	}

	return fmt.Sprintf("%s:%d", ip.String(), port), nil
}

func parseMappedAddress(data []byte) (string, error) {
	if len(data) < 8 {
		return "", fmt.Errorf("MAPPED-ADDRESS too short")
	}
	family := data[1]
	if family != 0x01 { // IPv4
		return "", fmt.Errorf("unsupported address family: %d", family)
	}

	port := binary.BigEndian.Uint16(data[2:4])
	ip := net.IP(data[4:8])

	return fmt.Sprintf("%s:%d", ip.String(), port), nil
}
