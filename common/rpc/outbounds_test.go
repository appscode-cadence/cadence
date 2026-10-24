// Copyright (c) 2021 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package rpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/yarpc"
	"go.uber.org/yarpc/api/peer"
	"go.uber.org/yarpc/api/transport"
	"go.uber.org/yarpc/encoding/raw"
	"go.uber.org/yarpc/peer/direct"
	"go.uber.org/yarpc/transport/grpc"
	"go.uber.org/yarpc/transport/tchannel"
	"google.golang.org/grpc/credentials"

	"github.com/uber/cadence/common/config"
	"github.com/uber/cadence/common/dynamicconfig/dynamicproperties"
	"github.com/uber/cadence/common/log/testlogger"
	"github.com/uber/cadence/common/metrics"
	"github.com/uber/cadence/common/service"
)

func TestCombineOutbounds(t *testing.T) {
	grpc := &grpc.Transport{}
	tchannel := &tchannel.Transport{}

	combined := CombineOutbounds()
	outbounds, err := combined.Build(grpc, tchannel)
	assert.NoError(t, err)
	assert.Empty(t, outbounds.Outbounds)

	combined = CombineOutbounds(fakeOutboundBuilder{err: errors.New("err-A")})
	_, err = combined.Build(grpc, tchannel)
	assert.EqualError(t, err, "err-A")

	combined = CombineOutbounds(
		fakeOutboundBuilder{outbounds: yarpc.Outbounds{"A": {}}},
		fakeOutboundBuilder{outbounds: yarpc.Outbounds{"A": {}}},
	)
	_, err = combined.Build(grpc, tchannel)
	assert.EqualError(t, err, "outbound \"A\" already configured")

	combined = CombineOutbounds(
		fakeOutboundBuilder{err: errors.New("err-A")},
		fakeOutboundBuilder{err: errors.New("err-B")},
	)
	_, err = combined.Build(grpc, tchannel)
	assert.EqualError(t, err, "err-A; err-B")

	combined = CombineOutbounds(
		fakeOutboundBuilder{outbounds: yarpc.Outbounds{"A": {}}},
		fakeOutboundBuilder{outbounds: yarpc.Outbounds{"B": {}, "C": {}}},
	)
	outbounds, err = combined.Build(grpc, tchannel)
	assert.NoError(t, err)
	assert.Equal(t, yarpc.Outbounds{
		"A": {},
		"B": {},
		"C": {},
	}, outbounds.Outbounds)
}

func TestPublicClientOutbound(t *testing.T) {
	makeConfig := func(hostPort string, transport string, enableAuth bool, keyPath string) *config.Config {
		return &config.Config{
			PublicClient:  config.PublicClient{HostPort: hostPort, Transport: transport},
			Authorization: config.Authorization{OAuthAuthorizer: config.OAuthAuthorizer{Enable: enableAuth}},
			ClusterGroupMetadata: &config.ClusterGroupMetadata{
				CurrentClusterName: "cluster-A",
				ClusterGroup: map[string]config.ClusterInformation{
					"cluster-A": {
						AuthorizationProvider: config.AuthorizationProvider{
							PrivateKey: keyPath,
						},
					},
				},
			},
		}
	}

	_, err := newPublicClientOutbound(&config.Config{})
	require.EqualError(t, err, "need to provide an endpoint config for PublicClient")

	builder, err := newPublicClientOutbound(makeConfig("localhost:1234", "tchannel", false, ""))
	require.NoError(t, err)
	require.NotNil(t, builder)
	require.Equal(t, "localhost:1234", builder.address)
	require.Equal(t, nil, builder.authMiddleware)
	require.False(t, builder.isGRPC)

	builder, err = newPublicClientOutbound(makeConfig("localhost:1234", "tchannel", true, "invalid"))
	require.EqualError(t, err, "create AuthProvider: invalid private key path invalid")
	require.False(t, builder.isGRPC)

	builder, err = newPublicClientOutbound(makeConfig("localhost:1234", "grpc", true, tempFile(t, "private-key")))
	require.NoError(t, err)
	require.NotNil(t, builder)
	require.Equal(t, "localhost:1234", builder.address)
	require.NotNil(t, builder.authMiddleware)
	require.True(t, builder.isGRPC)

	grpcTransport := grpc.NewTransport()
	tchannelTransport, err := tchannel.NewTransport(tchannel.ServiceName("test"))
	require.NoError(t, err)
	o, err := builder.Build(grpcTransport, tchannelTransport)
	require.NoError(t, err)
	outbounds := o.Outbounds
	assert.Equal(t, outbounds[OutboundPublicClient].ServiceName, service.Frontend)
	assert.NotNil(t, outbounds[OutboundPublicClient].Unary)
}

func TestPublicClientOutboundTLSConfig(t *testing.T) {
	makeConfig := func(transport string, tls config.TLS) *config.Config {
		return &config.Config{
			PublicClient: config.PublicClient{HostPort: "localhost:1234", Transport: transport, TLS: tls},
		}
	}

	builder, err := newPublicClientOutbound(makeConfig("grpc", config.TLS{}))
	require.NoError(t, err)
	assert.Nil(t, builder.tlsConfig)

	_, err = newPublicClientOutbound(makeConfig("tchannel", config.TLS{Enabled: true}))
	require.EqualError(t, err, "public client TLS is only supported with grpc transport")

	_, err = newPublicClientOutbound(makeConfig("grpc", config.TLS{Enabled: true, CaFile: "invalid"}))
	require.EqualError(t, err, "public client TLS config: open invalid: no such file or directory")

	builder, err = newPublicClientOutbound(makeConfig("grpc", config.TLS{Enabled: true}))
	require.NoError(t, err)
	assert.NotNil(t, builder.tlsConfig)
}

func TestPublicClientOutboundTLSHandshake(t *testing.T) {
	certs := newTestCerts(t)
	serverTLS, err := config.TLS{
		Enabled:           true,
		CertFile:          certs.serverCert,
		KeyFile:           certs.serverKey,
		CaFile:            certs.ca,
		RequireClientAuth: true,
	}.ToTLSConfig()
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serverTransport := grpc.NewTransport()
	server := yarpc.NewDispatcher(yarpc.Config{
		Name:     service.Frontend,
		Inbounds: yarpc.Inbounds{serverTransport.NewInbound(listener, grpc.InboundCredentials(credentials.NewTLS(serverTLS)))},
	})
	server.Register(raw.Procedure("echo", func(_ context.Context, body []byte) ([]byte, error) {
		return body, nil
	}))
	require.NoError(t, server.Start())
	defer server.Stop()

	call := func(clientTLS config.TLS) ([]byte, error) {
		builder, err := newPublicClientOutbound(&config.Config{
			PublicClient: config.PublicClient{HostPort: listener.Addr().String(), Transport: "grpc", TLS: clientTLS},
		})
		require.NoError(t, err)

		clientTransport := grpc.NewTransport()
		tchannelTransport, err := tchannel.NewTransport(tchannel.ServiceName("test"))
		require.NoError(t, err)
		outbounds, err := builder.Build(clientTransport, tchannelTransport)
		require.NoError(t, err)

		client := yarpc.NewDispatcher(yarpc.Config{Name: "test-client", Outbounds: outbounds.Outbounds})
		require.NoError(t, client.Start())
		defer client.Stop()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return raw.New(client.ClientConfig(OutboundPublicClient)).Call(ctx, "echo", []byte("hello"))
	}

	// mutual TLS with host verification succeeds
	resp, err := call(config.TLS{
		Enabled:                true,
		CertFile:               certs.clientCert,
		KeyFile:                certs.clientKey,
		CaFile:                 certs.ca,
		EnableHostVerification: true,
		ServerName:             "localhost",
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), resp)

	// without client certificate the server rejects the handshake
	_, err = call(config.TLS{Enabled: true, CaFile: certs.ca, EnableHostVerification: true, ServerName: "localhost"})
	assert.Error(t, err)

	// plaintext client cannot talk to a TLS-only server
	_, err = call(config.TLS{})
	assert.Error(t, err)
}

type testCerts struct {
	ca, serverCert, serverKey, clientCert, clientKey string
}

// newTestCerts writes a CA plus a server ("localhost") and a client certificate, all signed by the CA.
func newTestCerts(t *testing.T) testCerts {
	dir := t.TempDir()
	write := func(name string, typ string, der []byte) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600))
		return path
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leaf := func(serial int64, usage x509.ExtKeyUsage) ([]byte, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: "localhost"},
			DNSNames:     []string{"localhost"},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
		require.NoError(t, err)
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		return der, keyDER
	}
	serverDER, serverKeyDER := leaf(2, x509.ExtKeyUsageServerAuth)
	clientDER, clientKeyDER := leaf(3, x509.ExtKeyUsageClientAuth)

	return testCerts{
		ca:         write("ca.crt", "CERTIFICATE", caDER),
		serverCert: write("server.crt", "CERTIFICATE", serverDER),
		serverKey:  write("server.key", "PRIVATE KEY", serverKeyDER),
		clientCert: write("client.crt", "CERTIFICATE", clientDER),
		clientKey:  write("client.key", "PRIVATE KEY", clientKeyDER),
	}
}

func TestCrossDCOutbounds(t *testing.T) {
	grpcTransport := grpc.NewTransport()
	tchannelTransport, err := tchannel.NewTransport(tchannel.ServiceName("test"))
	require.NoError(t, err)

	clusterGroup := map[string]config.ClusterInformation{
		"cluster-A": {Enabled: true, RPCName: "cadence-frontend", RPCTransport: "invalid"},
	}
	_, err = NewCrossDCOutbounds(clusterGroup, &fakePeerChooserFactory{}).Build(grpcTransport, tchannelTransport)
	assert.EqualError(t, err, "unknown cross DC transport type: invalid")

	clusterGroup = map[string]config.ClusterInformation{
		"cluster-A": {Enabled: true, RPCName: "cadence-frontend", RPCTransport: "grpc", AuthorizationProvider: config.AuthorizationProvider{Enable: true, PrivateKey: "invalid path"}},
	}
	_, err = NewCrossDCOutbounds(clusterGroup, &fakePeerChooserFactory{}).Build(grpcTransport, tchannelTransport)
	assert.EqualError(t, err, "create AuthProvider: invalid private key path invalid path")

	clusterGroup = map[string]config.ClusterInformation{
		"cluster-A": {Enabled: true, RPCName: "cadence-frontend", RPCAddress: "address-A", RPCTransport: "grpc", AuthorizationProvider: config.AuthorizationProvider{Enable: true, PrivateKey: tempFile(t, "key")}},
		"cluster-B": {Enabled: true, RPCName: "cadence-frontend", RPCAddress: "address-B", RPCTransport: "tchannel"},
		"cluster-C": {Enabled: false},
	}
	o, err := NewCrossDCOutbounds(clusterGroup, &fakePeerChooserFactory{}).Build(grpcTransport, tchannelTransport)
	assert.NoError(t, err)
	outbounds := o.Outbounds
	assert.Equal(t, 2, len(outbounds))
	assert.Equal(t, "cadence-frontend", outbounds["cluster-A"].ServiceName)
	assert.Equal(t, "cadence-frontend", outbounds["cluster-B"].ServiceName)
	assert.NotNil(t, outbounds["cluster-A"].Unary)
	assert.NotNil(t, outbounds["cluster-B"].Unary)
}

func TestDirectOutbound(t *testing.T) {
	grpcTransport := grpc.NewTransport()
	tchannelTransport, err := tchannel.NewTransport(tchannel.ServiceName("test"))
	require.NoError(t, err)
	logger := testlogger.New(t)
	metricCl := metrics.NewNoopMetricsClient()
	falseFn := func(opts ...dynamicproperties.FilterOption) bool { return false }

	o, err := NewDirectOutboundBuilder("cadence-history", false, nil, NewDirectPeerChooserFactory("cadence-history", logger, metricCl), falseFn).Build(grpcTransport, tchannelTransport)
	assert.NoError(t, err)
	outbounds := o.Outbounds
	assert.Equal(t, "cadence-history", outbounds["cadence-history"].ServiceName)
	assert.NotNil(t, outbounds["cadence-history"].Unary)

	o, err = NewDirectOutboundBuilder("cadence-history", true, nil, NewDirectPeerChooserFactory("cadence-history", logger, metricCl), falseFn).Build(grpcTransport, tchannelTransport)
	assert.NoError(t, err)
	outbounds = o.Outbounds
	assert.Equal(t, "cadence-history", outbounds["cadence-history"].ServiceName)
	assert.NotNil(t, outbounds["cadence-history"].Unary)
}

func TestSingleGRPCOutbound(t *testing.T) {
	grpcTransport := grpc.NewTransport()
	tchannelTransport, err := tchannel.NewTransport(tchannel.ServiceName("test"))
	require.NoError(t, err)

	builder := NewSingleGRPCOutboundBuilder("grpc-only-out", "grpc-service-name", "http://example.com:1234")

	outBound, err := builder.Build(grpcTransport, tchannelTransport)
	assert.NoError(t, err)
	assert.Equal(t, "grpc-service-name", outBound.Outbounds["grpc-only-out"].ServiceName)
	assert.NotNil(t, outBound.Outbounds["grpc-only-out"].Unary)
}

func TestIsGRPCOutboud(t *testing.T) {
	grpcTransport := grpc.NewTransport()
	tchannelTransport, err := tchannel.NewTransport(tchannel.ServiceName("test"))
	require.NoError(t, err)

	assert.True(t, IsGRPCOutbound(&transport.OutboundConfig{Outbounds: transport.Outbounds{Unary: grpcTransport.NewSingleOutbound("localhost:1234")}}))
	assert.False(t, IsGRPCOutbound(&transport.OutboundConfig{Outbounds: transport.Outbounds{Unary: tchannelTransport.NewSingleOutbound("localhost:1234")}}))
	assert.Panics(t, func() {
		IsGRPCOutbound(&transport.OutboundConfig{Outbounds: transport.Outbounds{Unary: fakeOutbound{}}})
	})
}

func tempFile(t *testing.T, content string) string {
	f, err := ioutil.TempFile("", "")
	require.NoError(t, err)

	f.Write([]byte(content))
	require.NoError(t, err)

	err = f.Close()
	require.NoError(t, err)

	return f.Name()
}

type fakeOutboundBuilder struct {
	outbounds yarpc.Outbounds
	err       error
}

func (b fakeOutboundBuilder) Build(*grpc.Transport, *tchannel.Transport) (*Outbounds, error) {
	return &Outbounds{Outbounds: b.outbounds}, b.err
}

type fakePeerChooserFactory struct{}

func (f fakePeerChooserFactory) CreatePeerChooser(transport peer.Transport, opts PeerChooserOptions) (PeerChooser, error) {
	chooser, err := direct.New(direct.Configuration{}, transport)
	if err != nil {
		return nil, err
	}
	return &defaultPeerChooser{actual: chooser}, nil
}
