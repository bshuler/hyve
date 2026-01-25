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
	"hypot/auth"
	"hypot/client/packets"
	auth2 "hypot/client/packets/auth"
	"hypot/client/packets/connection"
	"hypot/client/packets/interface_"
	"hypot/client/packets/player"
	"hypot/client/packets/setup"
	"math/big"
	"strings"
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

func (c *HytaleClient) Connect() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
	conn, err := quic.DialAddr(ctx, dst, tls, qconf)
	if err != nil {
		return fmt.Errorf("QUIC dial failed: %w", err)
	}
	fmt.Println("QUIC connection established!")

	c.conn = conn

	c.ctx, c.cancel = context.WithCancel(context.Background())

	err = c.joinServer()
	if err != nil {
		return err
	}

	return nil
}

func (c *HytaleClient) Disconnect() error {
	p := connection.NewDisconnectPacket()
	pb, err := p.Encode()
	if err != nil {
		return err
	}

	if _, err := c.stream.Write(pb); err != nil {
		return err
	}

	if c.cancel != nil {
		c.cancel()
	}

	if err := c.stream.Close(); err != nil {
		return err
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

func (c *HytaleClient) joinServer() error {
	stream, err := c.conn.OpenStreamSync(context.Background())
	if err != nil {
		return err
	}
	defer stream.Close()

	c.stream = stream

	p := connection.NewConnectPacket(c.Id, c.Username, &c.Session.IdentityToken, "en", nil, nil)
	data, err := p.Encode()
	if err != nil {
		panic(err)
	}

	fmt.Printf("%x\n", data)

	fmt.Printf("Sending Connect packet (%d bytes)\n", len(data))
	fmt.Printf("Identity token length: %d\n", len(c.Session.IdentityToken))

	if _, err := c.stream.Write(data); err != nil {
		return err
	}

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

		n, err := stream.Read(tmp)
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
		if err != nil {
			return err
		}
	}

	return nil
}
