package analyze

import (
	"encoding/binary"
	"fmt"
)

// ParseObjectGUID parses binary ObjectGUID to string format
// binaryGUID: Binary representation of GUID
// Returns: Formatted GUID string (e.g., "{00000000-0000-0000-0000-000000000000}")
func ParseObjectGUID(binaryGUID []byte) (string, error) {
	// GUID must be 16 bytes long
	if len(binaryGUID) != 16 {
		return "", fmt.Errorf("invalid GUID length: expected 16 bytes, got %d", len(binaryGUID))
	}

	// Parse byte data in segments: 4-2-2-2-6 format
	guid := fmt.Sprintf("{%08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x}",
		binary.LittleEndian.Uint32(binaryGUID[0:4]), // Segment 1: 4 bytes little endian
		binary.LittleEndian.Uint16(binaryGUID[4:6]), // Segment 2: 2 bytes little endian
		binary.LittleEndian.Uint16(binaryGUID[6:8]), // Segment 3: 2 bytes little endian
		binary.BigEndian.Uint16(binaryGUID[8:10]),   // Segment 4 first 2 bytes: big endian
		binaryGUID[10], binaryGUID[11], binaryGUID[12], binaryGUID[13], binaryGUID[14], binaryGUID[15]) // Segment 4 remaining 6 bytes

	return guid, nil
}

// ParseObjectSID parses binary ObjectSID to string format
// binarySID: Binary representation of SID
// Returns: Formatted SID string (e.g., "S-1-5-21-3623811015-3361044348-30300820-1013")
func ParseObjectSID(binarySID []byte) (string, error) {
	// Check minimum length
	if len(binarySID) < 8 {
		return "", fmt.Errorf("SID too short: expected at least 8 bytes, got %d", len(binarySID))
	}

	// Parse revision
	rev := binarySID[0]
	if rev != 1 {
		return "", fmt.Errorf("unsupported SID revision: %d", rev)
	}

	// Parse sub-authority count (unsigned handling)
	subAuthCount := int(binarySID[1]) & 0xFF
	if subAuthCount < 0 || subAuthCount > 255 {
		return "", fmt.Errorf("invalid sub-authority count: %d", subAuthCount)
	}

	// Check data integrity
	requiredLen := 8 + subAuthCount*4
	if len(binarySID) < requiredLen {
		return "", fmt.Errorf("incomplete SID data: expected %d bytes, got %d", requiredLen, len(binarySID))
	}

	// Parse identifier authority (big endian)
	var authority uint64
	for _, v := range binarySID[2:8] {
		authority = (authority << 8) | uint64(v)
	}

	// Parse sub-authorities (little endian)
	sid := fmt.Sprintf("S-%d-%d", rev, authority)
	for i := 0; i < subAuthCount; i++ {
		start := 8 + i*4
		sub := binary.LittleEndian.Uint32(binarySID[start : start+4])
		sid += fmt.Sprintf("-%d", sub)
	}

	return sid, nil
}
