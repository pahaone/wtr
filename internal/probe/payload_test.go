package probe

import (
	"net/netip"
	"testing"
	"time"
)

func TestMakePayloadMarkerRoundTrip(t *testing.T) {
	buf := make([]byte, 56)
	p := MakePayload(buf, 56, 7, 12, 999)
	if len(p) != 56 {
		t.Fatalf("длина payload %d, хотим 56", len(p))
	}
	if !MatchMarker(p, 7, 12, 999) {
		t.Fatal("маркер не узнался собственным зондом")
	}
	// Any of the marker fields must break the match — otherwise stale replies are never rejected.
	for _, bad := range []struct{ c, s uint32 }{{8, 999}, {7, 1000}} {
		if MatchMarker(p, bad.c, 12, bad.s) {
			t.Errorf("цикл/seq (%d,%d) ложно совпал с (7,12,999)", bad.c, bad.s)
		}
	}
	for _, badTTL := range []int{11, 13, 268} {
		if MatchMarker(p, 7, badTTL, 999) {
			t.Errorf("ttl=%d ложно совпал с ttl=12", badTTL)
		}
	}
	if MatchMarker(p[:13], 7, 12, 999) {
		t.Error("обрезанный маркер не должен совпадать")
	}
}

// TestMakePayloadMinSize — the marker takes 14 bytes, a smaller payload must not be truncated.
func TestMakePayloadMinSize(t *testing.T) {
	buf := make([]byte, 64)
	p := MakePayload(buf, 4, 1, 1, 1)
	if len(p) < 14 {
		t.Fatalf("payload %d байт — маркер не влезет", len(p))
	}
	if !MatchMarker(p, 1, 1, 1) {
		t.Fatal("маркер повреждён при минимальном размере")
	}
}

// TestMakePayloadReusesBuffer checks that writing again into the same buffer leaves no
// traces of the previous probe (otherwise cross-accounting becomes possible).
func TestMakePayloadReusesBuffer(t *testing.T) {
	buf := make([]byte, 56)
	MakePayload(buf, 56, 1, 1, 1)
	p := MakePayload(buf, 56, 2, 2, 2)
	if MatchMarker(p, 1, 1, 1) {
		t.Error("старый маркер всё ещё узнаётся в переиспользованном буфере")
	}
	if !MatchMarker(p, 2, 2, 2) {
		t.Error("новый маркер не записан корректно")
	}
}

func TestClassifyContract(t *testing.T) {
	cases := []struct {
		status uint32
		want   Kind
	}{
		{0, KindReply},           // IP_SUCCESS
		{11013, KindHop},         // IP_TTL_EXPIRED_TRANSIT — the main working case
		{11010, KindTimeout},     // IP_REQ_TIMED_OUT
		{11003, KindUnreachable}, // IP_DEST_HOST_UNREACHABLE
		{11002, KindUnreachable}, // IP_DEST_NET_UNREACHABLE
		{1231, KindUnreachable},  // ERROR_NETWORK_UNREACHABLE (Win32 code)
		{11050, KindError},       // IP_GENERAL_FAILURE
		{0xFFFFFFFF, KindError},  // unknown code
	}
	for _, c := range cases {
		if got := Classify(c.status); got != c.want {
			t.Errorf("Classify(%d=%s) = %s, хотим %s", c.status, StatusName(c.status), got, c.want)
		}
	}
}

func TestShortFlag(t *testing.T) {
	cases := map[uint32]string{
		11003: "!H",
		11002: "!N",
		11005: "!X",
		11004: "!P",
		0:     "", // success must not get any flags
		11013: "", // an ordinary hop — no flags
	}
	for st, want := range cases {
		if got := ShortFlag(st); got != want {
			t.Errorf("ShortFlag(%d) = %q, хотим %q", st, got, want)
		}
	}
}

func TestReplyKind(t *testing.T) {
	r := Reply{From: netip.MustParseAddr("10.0.0.1"), Status: 11013, RTT: 3 * time.Millisecond}
	if r.Kind() != KindHop {
		t.Fatalf("Kind = %s, хотим hop", r.Kind())
	}
	if StatusName(11013) != "IP_TTL_EXPIRED_TRANSIT" {
		t.Errorf("StatusName(11013) = %q", StatusName(11013))
	}
}
