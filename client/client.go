package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	tls2 "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/bshuler/hyve/auth"
	"github.com/bshuler/hyve/client/packets"
	auth2 "github.com/bshuler/hyve/client/packets/auth"
	"github.com/bshuler/hyve/client/packets/connection"
	"github.com/bshuler/hyve/client/packets/interface_"
	"github.com/bshuler/hyve/client/packets/player"
	"github.com/bshuler/hyve/client/packets/setup"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
)

type HytaleClient struct {
	IP       string
	Port     int
	Username string
	Id       uuid.UUID
	Password *string
	Session  *auth.GameSession

	conn        *quic.Conn
	stream      *quic.Stream
	sc          *auth.SessionClient
	fingerprint string

	sentRequestAssets bool
	sentPlayerOptions bool
	sentClientReady   bool

	// handshakeDone is closed (exactly once) after the auth + join-world
	// handshake completes. Connect blocks on this so callers learn about
	// dial/auth failures synchronously.
	handshakeDone chan struct{}
	handshakeOnce sync.Once

	// runErr is buffered (1) and receives the read loop's terminal error
	// when it exits. Run() blocks on it; Connect() select-reads it so an
	// early read-loop failure aborts the handshake wait.
	runErr chan error

	// ctx/cancel control the lifetime of the read loop. Disconnect()
	// cancels them so the loop exits on the next iteration. They are
	// distinct from the context passed to Connect() (which only governs
	// the handshake-wait timeout).
	ctx    context.Context
	cancel context.CancelFunc
}

func NewHytaleClient(ip string, port int, profile *auth.Profile, password *string, ac *auth.AuthClient) *HytaleClient {
	return &HytaleClient{
		IP:       ip,
		Port:     port,
		Username: profile.Username,
		Id:       profile.Id,
		Password: password,
		sc:       auth.NewSessionClient(ac),
	}
}

// Connect establishes the QUIC connection, opens the game stream, sends
// the Connect packet, then spawns the read loop on a goroutine and waits
// for either:
//   - the handshake to complete (returns nil),
//   - the read loop to fail (returns its error),
//   - the supplied ctx to be cancelled or hit its deadline.
//
// The supplied ctx governs only the handshake-wait window; the read
// loop's own lifetime is controlled by an internal context cancelled by
// Disconnect.
func (c *HytaleClient) Connect(ctx context.Context) error {
	c.handshakeDone = make(chan struct{})
	c.runErr = make(chan error, 1)
	c.ctx, c.cancel = context.WithCancel(context.Background())

	if err := c.dialAndOpenStream(ctx); err != nil {
		c.cancel()
		return err
	}

	go func() {
		c.runErr <- c.readLoop()
	}()

	select {
	case <-c.handshakeDone:
		return nil
	case err := <-c.runErr:
		// Read loop failed before handshake completed. Push the error
		// back so Run() can still observe it, then return it.
		c.runErr <- err
		return err
	case <-ctx.Done():
		// Handshake timed out / caller cancelled. Tear down the loop
		// so it doesn't leak.
		c.cancel()
		return ctx.Err()
	}
}

// Run blocks until the read-loop goroutine exits, returning whatever
// error it produced (nil on a clean disconnect). It is safe to call
// Run after Connect returns nil; calling Run before Connect or after
// Disconnect will block forever / return immediately depending on
// internal state, so callers should only invoke it once per Connect.
func (c *HytaleClient) Run(ctx context.Context) error {
	select {
	case err := <-c.runErr:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// dialAndOpenStream performs the synchronous part of bringing up a
// connection: session creation, QUIC dial, stream open, and sending the
// initial Connect packet. After this returns nil, the server should
// respond with AuthGrant and the read loop can take over.
func (c *HytaleClient) dialAndOpenStream(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	s, err := c.sc.NewGameSession(c.Id)
	if err != nil {
		return fmt.Errorf("failed to create game session: %w", err)
	}
	c.Session = s

	dst := fmt.Sprintf("%s:%d", c.IP, c.Port)

	clientCert, fingerprint, err := c.generateClientCert()
	if err != nil {
		return fmt.Errorf("failed to generate client cert: %w", err)
	}

	c.fingerprint = fingerprint

	tls := &tls2.Config{
		InsecureSkipVerify: true,
		Certificates: []tls2.Certificate{
			clientCert,
		},
		NextProtos: []string{"hytale/1", "hytale/2"},
	}

	qconf := &quic.Config{
		HandshakeIdleTimeout: 10 * time.Second,
		MaxIdleTimeout:       30 * time.Second,
	}

	fmt.Println("Starting QUIC dial...")
	conn, err := quic.DialAddr(dialCtx, dst, tls, qconf)
	if err != nil {
		return fmt.Errorf("QUIC dial failed: %w", err)
	}
	fmt.Println("QUIC connection established!")

	c.conn = conn

	stream, err := c.conn.OpenStreamSync(dialCtx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	c.stream = stream

	p := connection.NewConnectPacket(c.Id, c.Username, &c.Session.IdentityToken, "en", nil, nil)
	data, err := p.Encode()
	if err != nil {
		return fmt.Errorf("encode connect packet: %w", err)
	}

	fmt.Printf("Sending Connect packet (%d bytes)\n", len(data))
	fmt.Printf("Identity token length: %d\n", len(c.Session.IdentityToken))

	if _, err := c.stream.Write(data); err != nil {
		return fmt.Errorf("write connect packet: %w", err)
	}

	return nil
}

func (c *HytaleClient) Disconnect() error {
	p := connection.NewDisconnectPacket()
	pb, err := p.Encode()
	if err != nil {
		return err
	}

	if c.stream != nil {
		if _, err := c.stream.Write(pb); err != nil {
			// Continue with teardown even if the disconnect packet
			// failed to send — the server side will GC us anyway.
		}
	}

	if c.cancel != nil {
		c.cancel()
	}

	if c.stream != nil {
		_ = c.stream.Close()
	}
	if c.conn != nil {
		return c.conn.CloseWithError(0, "client disconnect")
	}

	return nil
}

func (c *HytaleClient) generateClientCert() (tls2.Certificate, string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls2.Certificate{}, "", err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "HytaleClient",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls2.Certificate{}, "", err
	}

	hash := sha256.Sum256(certDER)
	fingerprint := base64.RawURLEncoding.EncodeToString(hash[:])

	cert := tls2.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}

	return cert, fingerprint, nil
}

func (c *HytaleClient) processPacket(packetId int, payload []byte) error {
	switch packetId {
	case packets.AuthGrantPacketId:
		packet, err := auth2.DecodeAuthGrant(payload)
		if err != nil {
			return err
		}

		err = c.processAuthGrantPacket(packet)
		if err != nil {
			return err
		}
	case packets.ServerInfoPacketId:
		if !c.sentRequestAssets {
			if err := c.processServerInfoPacket(); err != nil {
				return err
			}
			c.sentRequestAssets = true
		}
	case packets.WorldLoadProgressPacketId:
		if !c.sentPlayerOptions {
			if err := c.processWorldLoadProgressPacket(); err != nil {
				return err
			}
			c.sentPlayerOptions = true
		}
	case packets.JoinWorldPacketId:
		if !c.sentClientReady {
			if err := c.processJoinWorldPacket(); err != nil {
				return err
			}
			c.sentClientReady = true
			c.signalHandshakeDone()
		}
	case packets.AddToServerPlaylistPacketId:
		p, err := interface_.DecodeAddToServerPlayerList(payload)
		if err != nil {
			return err
		}

		fmt.Println("player count: ", p.PlayerCount)

		for i := 0; i < int(p.PlayerCount); i++ {
			fmt.Println("player ", p.Players[i].Username)
			fmt.Println("id ", p.Players[i].Id)
		}
	case packets.SetClientIdPacketId:
		// On Set client id ready
	case packets.PingPacketId:
		p, err := connection.DecodePing(payload)
		if err != nil {
			return err
		}

		pr := connection.NewPongPacket(p.Id)
		prb, err := pr.Encode()
		if err != nil {
			return err
		}

		_, err = c.stream.Write(prb)
		if err != nil {
			return err
		}
	case packets.ServerMessagePacketId:
		p, ok, err := interface_.DecodeServerMessage(payload)
		if err != nil {
			return err
		}
		if !ok || p == nil {
			break // ignore non-chat server messages
		}

		fmt.Println("Received message: ", p.Username, " - ", p.Message)
		if p.Message == "leave" {
			pl := interface_.NewChatMessagePacket("ok fine")
			plb, err := pl.Encode()
			if err != nil {
				return err
			}

			c.stream.Write(plb)
			if err := c.Disconnect(); err != nil {
				return err
			}
		} else if strings.HasPrefix("say", p.Message) {
			pl := interface_.NewChatMessagePacket(strings.TrimPrefix(p.Message, "say"))
			plb, err := pl.Encode()
			if err != nil {
				return err
			}

			c.stream.Write(plb)
		}

	default:
		//fmt.Println("Received ", packetId)
		return nil
	}

	return nil
}

// signalHandshakeDone closes the handshakeDone channel exactly once.
// Exposed as a method (not inlined) so unit tests can drive it directly.
func (c *HytaleClient) signalHandshakeDone() {
	c.handshakeOnce.Do(func() {
		if c.handshakeDone != nil {
			close(c.handshakeDone)
		}
	})
}

func (c *HytaleClient) processJoinWorldPacket() error {
	cr := player.NewClientReadyPacket(true, false)
	b, err := cr.Encode()
	if err != nil {
		return err
	}

	if _, err := c.stream.Write(b); err != nil {
		return err
	}

	cr = player.NewClientReadyPacket(false, true)
	b, err = cr.Encode()
	if err != nil {
		return err
	}

	if _, err := c.stream.Write(b); err != nil {
		return err
	}
	return nil
}

func (c *HytaleClient) processWorldLoadProgressPacket() error {
	po := setup.NewPlayerOptionsPacket()
	b, err := po.Encode()
	if err != nil {
		return err
	}

	if _, err := c.stream.Write(b); err != nil {
		return err
	}
	return nil
}

func (c *HytaleClient) processServerInfoPacket() error {
	p := setup.NewRequestAssetsPacket()
	b, err := p.Encode()
	if err != nil {
		return err
	}

	if _, err := c.stream.Write(b); err != nil {
		return err
	}
	return nil
}

func (c *HytaleClient) processAuthGrantPacket(packet *auth2.AuthGrant) error {
	at, err := c.sc.ExchangeAuthToken(c.fingerprint, *packet.AuthorizationGrant, c.Session.SessionToken)
	if err != nil {
		return err
	}

	gt, err := c.sc.ExchangeAuthGrant(*packet.ServerIdentityToken, c.Session.SessionToken)
	if err != nil {
		return err
	}

	fmt.Println("[at] ", at)
	fmt.Println("[gt] ", gt)

	atp := auth2.NewAuthTokenPacket(at, gt)
	d, err := atp.Encode()
	if err != nil {
		return err
	}

	if _, err := c.stream.Write(d); err != nil {
		return err
	}
	return nil
}

// readLoop runs the in-stream packet read loop until the lifetime
// context is cancelled or the stream errors. It owns the stream's
// Close() — Disconnect() cancels the context, which exits the loop,
// which closes the stream on its way out.
func (c *HytaleClient) readLoop() error {
	defer func() {
		if c.stream != nil {
			_ = c.stream.Close()
		}
	}()

	var acc []byte
	tmp := make([]byte, 64*1024)

	for {
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		default:
		}

		if err := c.stream.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			return err
		}

		n, err := c.stream.Read(tmp)
		if err != nil {
			if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
				continue
			}
			return err
		}
		if n > 0 {
			acc = append(acc, tmp[:n]...)

			for {
				if len(acc) < 8 {
					break
				}
				payloadLen := binary.LittleEndian.Uint32(acc[0:4])
				packetID := int(binary.LittleEndian.Uint32(acc[4:8]))
				frameLen := int(8 + payloadLen)

				if len(acc) < frameLen {
					break
				}

				payload := acc[8:frameLen]
				if err := c.processPacket(packetID, payload); err != nil {
					fmt.Println(err)
				}

				acc = acc[frameLen:]
			}
		}
	}
}
