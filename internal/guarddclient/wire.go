package guarddclient

import (
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

func putVarint(v uint64) []byte {
	b := make([]byte, 0, 10)
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}
func putBytes(n uint64, b []byte) []byte {
	o := putVarint(n<<3 | 2)
	o = append(o, putVarint(uint64(len(b)))...)
	return append(o, b...)
}
func putText(n uint64, s string) []byte { return putBytes(n, []byte(s)) }
func putUint(n, v uint64) []byte        { o := putVarint(n << 3); return append(o, putVarint(v)...) }
func (f requestFrame) encode() []byte {
	var o []byte
	o = append(o, putText(1, f.Protocol)...)
	o = append(o, putText(2, f.Method)...)
	o = append(o, putText(3, f.RequestID)...)
	o = append(o, putBytes(4, f.Nonce)...)
	o = append(o, putUint(5, f.IssuedAt)...)
	o = append(o, putUint(6, f.ExpiresAt)...)
	o = append(o, putText(7, f.IssuerID)...)
	o = append(o, putText(8, f.KeyID)...)
	o = append(o, putText(9, f.BootID)...)
	o = append(o, putUint(10, f.ExpectedStateVersion)...)
	o = append(o, putBytes(11, f.BindingCBOR)...)
	o = append(o, putBytes(12, f.PayloadCBOR)...)
	o = append(o, putBytes(13, f.Authorization)...)
	return o
}
func readVarint(b []byte, p *int) (uint64, error) {
	start := *p
	var v uint64
	for shift := uint(0); shift < 70; shift += 7 {
		if *p >= len(b) {
			return 0, errors.New("truncated protobuf varint")
		}
		x := b[*p]
		*p++
		if shift == 63 && x > 1 {
			return 0, errors.New("protobuf overflow")
		}
		v |= uint64(x&127) << shift
		if x&128 == 0 {
			if !equal(b[start:*p], putVarint(v)) {
				return 0, errors.New("non-minimal protobuf varint")
			}
			return v, nil
		}
	}
	return 0, errors.New("protobuf varint too long")
}
func decodeResponse(b []byte) (responseFrame, error) {
	var r responseFrame
	seen := map[uint64]bool{}
	p := 0
	for p < len(b) {
		tag, e := readVarint(b, &p)
		if e != nil {
			return r, e
		}
		n, w := tag>>3, tag&7
		if n < 1 || n > 6 {
			return r, errors.New("unknown protobuf field")
		}
		if seen[n] {
			return r, errors.New("duplicate protobuf field")
		}
		seen[n] = true
		if n == 3 {
			if w != 0 {
				return r, errors.New("protobuf wire mismatch")
			}
			v, e := readVarint(b, &p)
			if e != nil || v > 1 {
				return r, errors.New("invalid protobuf bool")
			}
			r.OK = v == 1
			continue
		}
		if w != 2 {
			return r, errors.New("protobuf wire mismatch")
		}
		l, e := readVarint(b, &p)
		if e != nil || l > maxFrame || int(l) > len(b)-p {
			return r, errors.New("invalid protobuf length")
		}
		v := b[p : p+int(l)]
		p += int(l)
		switch n {
		case 1:
			if !utf8.Valid(v) {
				return r, errors.New("invalid UTF-8")
			}
			r.Protocol = string(v)
		case 2:
			r.RequestID = string(v)
		case 4:
			r.Payload = append([]byte(nil), v...)
		case 5:
			r.ErrorCode = string(v)
		case 6:
			r.ErrorMessage = string(v)
		}
	}
	if len(seen) != 6 {
		return r, errors.New("missing protobuf response field")
	}
	return r, nil
}

func packetPayload(packet []byte) ([]byte, error) {
	if len(packet) < 4 {
		return nil, errors.New("missing frame length")
	}
	n := binary.BigEndian.Uint32(packet)
	if n == 0 || int(n) != len(packet)-4 || n > maxFrame-4 {
		return nil, errors.New("frame length mismatch")
	}
	return packet[4:], nil
}
