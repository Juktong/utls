package tls

import (
	"bytes"
	"net"
	"testing"
)

type incrementingSource struct {
	next byte
}

func (s *incrementingSource) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = s.next
		s.next++
	}
	return len(b), nil
}

func findKeyShareExtension(t *testing.T, exts []TLSExtension) *KeyShareExtension {
	t.Helper()

	for _, ext := range exts {
		if keyShareExt, ok := ext.(*KeyShareExtension); ok {
			return keyShareExt
		}
	}

	t.Fatal("key_share extension not found")
	return nil
}

func findKeyShareData(t *testing.T, keyShareExt *KeyShareExtension, group CurveID) []byte {
	t.Helper()

	for _, keyShare := range keyShareExt.KeyShares {
		if keyShare.Group == group {
			return keyShare.Data
		}
	}

	t.Fatalf("key_share for group %v not found", group)
	return nil
}

func newTestUConnWithIncrementingRand() *UConn {
	return UClient(&net.TCPConn{}, &Config{
		ServerName: "example.com",
		Rand:       &incrementingSource{},
	}, HelloCustom)
}

func fingerprintsWithHybridClassicalKeyShareReuse() []ClientHelloID {
	return []ClientHelloID{
		HelloFirefox_148,
	}
}

func TestParrotFingerprintsReuseHybridClassicalKeyShare(t *testing.T) {
	for _, helloID := range fingerprintsWithHybridClassicalKeyShareReuse() {
		t.Run(helloID.Str(), func(t *testing.T) {
			spec, err := UTLSIdToSpec(helloID)
			if err != nil {
				t.Fatalf("unexpected error creating %s spec: %v", helloID.Str(), err)
			}

			uconn := newTestUConnWithIncrementingRand()
			if err := uconn.ApplyPreset(&spec); err != nil {
				t.Fatalf("unexpected error applying %s spec: %v", helloID.Str(), err)
			}

			keyShareExt := findKeyShareExtension(t, uconn.Extensions)
			hybridData := findKeyShareData(t, keyShareExt, X25519MLKEM768)
			classicalData := findKeyShareData(t, keyShareExt, X25519)

			if len(hybridData) < x25519PublicKeySize {
				t.Fatalf("hybrid keyshare is too short: got %d bytes", len(hybridData))
			}
			hybridClassicalPart := hybridData[len(hybridData)-x25519PublicKeySize:]
			if !bytes.Equal(hybridClassicalPart, classicalData) {
				t.Fatalf("expected %s to reuse classical keyshare: hybrid classical part != X25519 keyshare", helloID.Str())
			}

			keys := uconn.HandshakeState.State13.KeyShareKeys
			if keys == nil || keys.MlkemEcdhe == nil || keys.Ecdhe == nil {
				t.Fatal("expected both hybrid and classical ECDHE private keys to be set")
			}
			if keys.MlkemEcdhe != keys.Ecdhe {
				t.Fatalf("expected %s hybrid/classical keyshares to reuse the same ECDHE private key", helloID.Str())
			}

			keysByGroup := uconn.HandshakeState.State13.KeyShareKeysByGroup
			hybridKeys := keysByGroup[X25519MLKEM768]
			classicalKeys := keysByGroup[X25519]
			p256Keys := keysByGroup[CurveP256]
			if hybridKeys == nil || hybridKeys.Mlkem == nil || hybridKeys.MlkemEcdhe == nil {
				t.Fatal("expected complete hybrid private key material")
			}
			if classicalKeys == nil || classicalKeys.Ecdhe == nil {
				t.Fatal("expected X25519 private key material")
			}
			if p256Keys == nil || p256Keys.Ecdhe == nil {
				t.Fatal("expected P-256 private key material")
			}
			if hybridKeys.MlkemEcdhe != classicalKeys.Ecdhe {
				t.Fatal("expected per-group hybrid/classical keys to reuse the same ECDHE private key")
			}
			p256Data := findKeyShareData(t, keyShareExt, CurveP256)
			if !bytes.Equal(p256Keys.Ecdhe.PublicKey().Bytes(), p256Data) {
				t.Fatal("P-256 private key does not match the advertised key share")
			}
		})
	}
}

func TestHybridClassicalKeySharesAreIndependentByDefault(t *testing.T) {
	spec := ClientHelloSpec{
		TLSVersMin: VersionTLS12,
		TLSVersMax: VersionTLS13,
		CipherSuites: []uint16{
			TLS_AES_128_GCM_SHA256,
		},
		CompressionMethods: []uint8{compressionNone},
		Extensions: []TLSExtension{
			&SupportedCurvesExtension{
				Curves: []CurveID{
					X25519MLKEM768,
					X25519,
				},
			},
			&KeyShareExtension{
				KeyShares: []KeyShare{
					{
						Group: X25519MLKEM768,
					},
					{
						Group: X25519,
					},
				},
			},
			&SupportedVersionsExtension{
				Versions: []uint16{
					VersionTLS13,
					VersionTLS12,
				},
			},
		},
	}

	uconn := newTestUConnWithIncrementingRand()
	if err := uconn.ApplyPreset(&spec); err != nil {
		t.Fatalf("unexpected error applying independent keyshare spec: %v", err)
	}

	keyShareExt := findKeyShareExtension(t, uconn.Extensions)
	hybridData := findKeyShareData(t, keyShareExt, X25519MLKEM768)
	classicalData := findKeyShareData(t, keyShareExt, X25519)

	if len(hybridData) < x25519PublicKeySize {
		t.Fatalf("hybrid keyshare is too short: got %d bytes", len(hybridData))
	}
	hybridClassicalPart := hybridData[len(hybridData)-x25519PublicKeySize:]
	if bytes.Equal(hybridClassicalPart, classicalData) {
		t.Fatalf("expected independent keyshares by default: hybrid classical part == X25519 keyshare")
	}

	keys := uconn.HandshakeState.State13.KeyShareKeys
	if keys == nil || keys.MlkemEcdhe == nil || keys.Ecdhe == nil {
		t.Fatal("expected both hybrid and classical ECDHE private keys to be set")
	}
	if keys.MlkemEcdhe == keys.Ecdhe {
		t.Fatal("expected independent keyshares by default: hybrid/classical ECDHE private keys should differ")
	}

	keysByGroup := uconn.HandshakeState.State13.KeyShareKeysByGroup
	hybridKeys := keysByGroup[X25519MLKEM768]
	classicalKeys := keysByGroup[X25519]
	if hybridKeys == nil || hybridKeys.MlkemEcdhe == nil {
		t.Fatal("expected hybrid private key material")
	}
	if classicalKeys == nil || classicalKeys.Ecdhe == nil {
		t.Fatal("expected classical private key material")
	}
	if hybridKeys.MlkemEcdhe == classicalKeys.Ecdhe {
		t.Fatal("expected per-group hybrid/classical ECDHE private keys to differ")
	}
}

func processServerHelloForKeyShareSelection(
	t *testing.T,
	current *keySharePrivateKeys,
	keysByGroup map[CurveID]*KeySharePrivateKeys,
	offeredGroups []CurveID,
	selectedGroup CurveID,
) *keySharePrivateKeys {
	t.Helper()

	keyShares := make([]keyShare, len(offeredGroups))
	for i, group := range offeredGroups {
		keyShares[i].group = group
	}

	conn := &Conn{didHRR: true}
	uconn := &UConn{
		Conn: conn,
		HandshakeState: PubClientHandshakeState{
			State13: TLS13OnlyState{KeyShareKeysByGroup: keysByGroup},
		},
	}
	hs := &clientHandshakeStateTLS13{
		c:            conn,
		hello:        &clientHelloMsg{keyShares: keyShares},
		serverHello:  &serverHelloMsg{serverShare: keyShare{group: selectedGroup}},
		keyShareKeys: current,
		uconn:        uconn,
	}

	if err := hs.processServerHello(); err != nil {
		t.Fatalf("processServerHello failed: %v", err)
	}
	return hs.keyShareKeys
}

func TestProcessServerHelloSelectsSecondaryKeyShareAfterCookieOnlyHRR(t *testing.T) {
	// A cookie-only HRR keeps the original key shares. This constructs the
	// private state seen when processHelloRetryRequest has read the final
	// ServerHello and the server selects the secondary offered group.
	x25519Key, err := generateECDHEKey(&incrementingSource{}, X25519)
	if err != nil {
		t.Fatalf("failed to generate X25519 key: %v", err)
	}
	p256Key, err := generateECDHEKey(&incrementingSource{}, CurveP256)
	if err != nil {
		t.Fatalf("failed to generate P-256 key: %v", err)
	}

	selected := processServerHelloForKeyShareSelection(
		t,
		&keySharePrivateKeys{curveID: X25519, ecdhe: x25519Key},
		map[CurveID]*KeySharePrivateKeys{
			X25519:    {CurveID: X25519, Ecdhe: x25519Key},
			CurveP256: {CurveID: CurveP256, Ecdhe: p256Key},
		},
		[]CurveID{X25519, CurveP256},
		CurveP256,
	)

	if selected.curveID != CurveP256 || selected.ecdhe != p256Key {
		t.Fatal("final ServerHello did not select the retained secondary P-256 private key")
	}
}

func TestProcessServerHelloKeepsHelloRetryRequestKey(t *testing.T) {
	p384Key, err := generateECDHEKey(&incrementingSource{}, CurveP384)
	if err != nil {
		t.Fatalf("failed to generate P-384 key: %v", err)
	}

	hrrKeys := &keySharePrivateKeys{curveID: CurveP384, ecdhe: p384Key}
	selected := processServerHelloForKeyShareSelection(
		t,
		hrrKeys,
		map[CurveID]*KeySharePrivateKeys{
			CurveP384: {CurveID: CurveP384},
		},
		[]CurveID{CurveP384},
		CurveP384,
	)

	if selected != hrrKeys {
		t.Fatal("preset registry replaced the fresh private key generated for HelloRetryRequest")
	}
}

func TestProcessServerHelloKeepsCallerProvidedKeyShareKeys(t *testing.T) {
	p256Key, err := generateECDHEKey(&incrementingSource{}, CurveP256)
	if err != nil {
		t.Fatalf("failed to generate P-256 key: %v", err)
	}
	x25519Key, err := generateECDHEKey(&incrementingSource{}, X25519)
	if err != nil {
		t.Fatalf("failed to generate X25519 key: %v", err)
	}

	tests := []struct {
		name    string
		group   CurveID
		current *keySharePrivateKeys
	}{
		{
			name:    "classical group inferred from ECDHE curve",
			group:   CurveP256,
			current: &keySharePrivateKeys{ecdhe: p256Key},
		},
		{
			name:    "hybrid group identified by explicit CurveID",
			group:   X25519MLKEM768,
			current: &keySharePrivateKeys{curveID: X25519MLKEM768, ecdhe: x25519Key},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selected := processServerHelloForKeyShareSelection(
				t,
				test.current,
				map[CurveID]*KeySharePrivateKeys{
					test.group: {CurveID: test.group},
				},
				[]CurveID{test.group},
				test.group,
			)

			if selected != test.current {
				t.Fatal("generated registry replaced caller-provided private key material")
			}
		})
	}
}
