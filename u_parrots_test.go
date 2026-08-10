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

func TestTLS13OnlyStateSelectKeyShareKeys(t *testing.T) {
	manualP256, err := generateECDHEKey(&incrementingSource{}, CurveP256)
	if err != nil {
		t.Fatalf("failed to generate manual P-256 key: %v", err)
	}

	fallback := &KeySharePrivateKeys{Ecdhe: manualP256}
	generatedP256 := &KeySharePrivateKeys{CurveID: CurveP256}
	x25519Keys := &KeySharePrivateKeys{CurveID: X25519}
	state := TLS13OnlyState{
		KeyShareKeys: fallback,
		KeyShareKeysByGroup: map[CurveID]*KeySharePrivateKeys{
			CurveP256: generatedP256,
			X25519:    x25519Keys,
		},
	}

	state.selectKeyShareKeys(CurveP256)
	if state.KeyShareKeys != fallback {
		t.Fatal("generated group replaced caller-provided key share keys")
	}

	state.selectKeyShareKeys(X25519)
	if state.KeyShareKeys != x25519Keys {
		t.Fatal("offered group did not select its private key material")
	}
}
