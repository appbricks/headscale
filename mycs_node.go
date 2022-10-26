package headscale

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	grpcMiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	zerolog "github.com/philip-bui/grpc-zerolog"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	zl "github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

var (
	MachineRegisteredTrigger func(machine *Machine)
	MachineExpiredTrigger    func(machine *Machine)

	MapTailscaleDNSConfig func(dnsConfig *tailcfg.DNSConfig)

	stopFn func() error
)

func (h *Headscale) DB() *gorm.DB {
	return h.db
}

// headscale.Serve with shutdown 
// code move to a Stop function
func (h *Headscale) Start() error {
	var err error

	// Fetch an initial DERP Map before we start serving
	h.DERPMap = GetDERPMap(h.cfg.DERP)

	if h.cfg.DERP.ServerEnabled {
		// When embedded DERP is enabled we always need a STUN server
		if h.cfg.DERP.STUNAddr == "" {
			return errSTUNAddressNotSet
		}

		h.DERPMap.Regions[h.DERPServer.region.RegionID] = &h.DERPServer.region
		go h.ServeSTUN()
	}

	if h.cfg.DERP.AutoUpdate {
		derpMapCancelChannel := make(chan struct{})
		defer func() { derpMapCancelChannel <- struct{}{} }()
		go h.scheduledDERPMapUpdateWorker(derpMapCancelChannel)
	}

	// MyCS: patched to retrieve ticker of expire 
	//       job so it can be cleanly shutdown
	expireNodesTicker := h.expireEphemeralNodesPatch(updateInterval)

	if zl.GlobalLevel() == zl.TraceLevel {
		zerolog.RespLog = true
	} else {
		zerolog.RespLog = false
	}

	// Prepare group for running listeners
	errorGroup := new(errgroup.Group)

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	//
	//
	// Set up LOCAL listeners
	//

	err = h.ensureUnixSocketIsAbsent()
	if err != nil {
		return fmt.Errorf("unable to remove old socket file: %w", err)
	}

	socketListener, err := net.Listen("unix", h.cfg.UnixSocket)
	if err != nil {
		return fmt.Errorf("failed to set up gRPC socket: %w", err)
	}

	// Change socket permissions
	if err := os.Chmod(h.cfg.UnixSocket, h.cfg.UnixSocketPermission); err != nil {
		return fmt.Errorf("failed change permission of gRPC socket: %w", err)
	}

	grpcGatewayMux := runtime.NewServeMux()

	// Make the grpc-gateway connect to grpc over socket
	grpcGatewayConn, err := grpc.Dial(
		h.cfg.UnixSocket,
		[]grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(GrpcSocketDialer),
		}...,
	)
	if err != nil {
		return err
	}

	// Connect to the gRPC server over localhost to skip
	// the authentication.
	err = v1.RegisterHeadscaleServiceHandler(ctx, grpcGatewayMux, grpcGatewayConn)
	if err != nil {
		return err
	}

	// Start the local gRPC server without TLS and without authentication
	grpcSocket := grpc.NewServer(zerolog.UnaryInterceptor())

	v1.RegisterHeadscaleServiceServer(grpcSocket, newHeadscaleV1APIServer(h))
	reflection.Register(grpcSocket)

	errorGroup.Go(func() error { return grpcSocket.Serve(socketListener) })

	//
	//
	// Set up REMOTE listeners
	//

	tlsConfig, err := h.getTLSSettings()
	if err != nil {
		log.Error().Err(err).Msg("Failed to set up TLS configuration")

		return err
	}

	//
	//
	// gRPC setup
	//

	// We are sadly not able to run gRPC and HTTPS (2.0) on the same
	// port because the connection mux does not support matching them
	// since they are so similar. There is multiple issues open and we
	// can revisit this if changes:
	// https://github.com/soheilhy/cmux/issues/68
	// https://github.com/soheilhy/cmux/issues/91

	var grpcServer *grpc.Server
	var grpcListener net.Listener
	if tlsConfig != nil || h.cfg.GRPCAllowInsecure {
		log.Info().Msgf("Headscale enabling remote gRPC at %s", h.cfg.GRPCAddr)

		grpcOptions := []grpc.ServerOption{
			grpc.UnaryInterceptor(
				grpcMiddleware.ChainUnaryServer(
					h.grpcAuthenticationInterceptor,
					zerolog.NewUnaryServerInterceptor(),
				),
			),
		}

		if tlsConfig != nil {
			grpcOptions = append(grpcOptions,
				grpc.Creds(credentials.NewTLS(tlsConfig)),
			)
		} else {
			log.Warn().Msg("gRPC is running without security")
		}

		grpcServer = grpc.NewServer(grpcOptions...)

		v1.RegisterHeadscaleServiceServer(grpcServer, newHeadscaleV1APIServer(h))
		reflection.Register(grpcServer)

		grpcListener, err = net.Listen("tcp", h.cfg.GRPCAddr)
		if err != nil {
			return fmt.Errorf("failed to bind to TCP address: %w", err)
		}

		errorGroup.Go(func() error { return grpcServer.Serve(grpcListener) })

		log.Info().
			Msgf("Headscale listening and serving gRPC on: %s", h.cfg.GRPCAddr)
	}

	//
	//
	// HTTP setup
	//
	// This is the regular router that we expose
	// over our main Addr. It also serves the legacy Tailcale API
	router := h.createRouter(grpcGatewayMux)

	// This router is served only over the Noise connection, and exposes only the new API.
	//
	// The HTTP2 server that exposes this router is created for
	// a single hijacked connection from /ts2021, using netutil.NewOneConnListener
	h.noiseMux = h.createNoiseMux()

	httpServer := &http.Server{
		Addr:        h.cfg.Addr,
		Handler:     router,
		ReadTimeout: HTTPReadTimeout,
		// Go does not handle timeouts in HTTP very well, and there is
		// no good way to handle streaming timeouts, therefore we need to
		// keep this at unlimited and be careful to clean up connections
		// https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/#aboutstreaming
		WriteTimeout: 0,
	}

	var httpListener net.Listener
	if tlsConfig != nil {
		httpServer.TLSConfig = tlsConfig
		httpListener, err = tls.Listen("tcp", h.cfg.Addr, tlsConfig)
	} else {
		httpListener, err = net.Listen("tcp", h.cfg.Addr)
	}
	if err != nil {
		return fmt.Errorf("failed to bind to TCP address: %w", err)
	}

	errorGroup.Go(func() error { return httpServer.Serve(httpListener) })

	log.Info().
		Msgf("Headscale listening and serving HTTP on: %s", h.cfg.Addr)

	promMux := http.NewServeMux()
	promMux.Handle("/metrics", promhttp.Handler())

	promHTTPServer := &http.Server{
		Addr:         h.cfg.MetricsAddr,
		Handler:      promMux,
		ReadTimeout:  HTTPReadTimeout,
		WriteTimeout: 0,
	}

	var promHTTPListener net.Listener
	promHTTPListener, err = net.Listen("tcp", h.cfg.MetricsAddr)

	if err != nil {
		return fmt.Errorf("failed to bind to TCP address: %w", err)
	}

	errorGroup.Go(func() error { return promHTTPServer.Serve(promHTTPListener) })

	log.Info().
		Msgf("Headscale listening and serving metrics on: %s", h.cfg.MetricsAddr)

	h.shutdownChan = make(chan struct{})

	stopFn = func() error {
		log.Info().
			Msg("Headscale Shutting down gracefully")

		if expireNodesTicker != nil {
			expireNodesTicker.Stop()
		}

		close(h.shutdownChan)
		h.pollNetMapStreamWG.Wait()

		// Gracefully shut down servers
		ctx, cancel := context.WithTimeout(
			context.Background(),
			HTTPShutdownTimeout,
		)
		if err := promHTTPServer.Shutdown(ctx); err != nil {
			log.Error().Err(err).Msg("Failed to shutdown prometheus http")
		}
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Error().Err(err).Msg("Failed to shutdown http")
		}
		grpcSocket.GracefulStop()

		if grpcServer != nil {
			grpcServer.GracefulStop()
			grpcListener.Close()
		}

		// Close network listeners
		promHTTPListener.Close()
		httpListener.Close()
		grpcGatewayConn.Close()

		// Stop listening (and unlink the socket if unix type):
		socketListener.Close()

		// Close db connections
		db, err := h.db.DB()
		if err != nil {
			log.Error().Err(err).Msg("Failed to get db handle")
		}
		err = db.Close()
		if err != nil {
			log.Error().Err(err).Msg("Failed to close db")
		}

		log.Info().
			Msg("Headscale stopped")

		// And we're done:
		cancel()

		return errorGroup.Wait()
	}

	return nil
}

func (h *Headscale) Stop() error {
	if stopFn != nil {
		return stopFn()
	}

	return nil
}

// Note: this a copy of Headscale.expireEphemeralNodes that
// returns the ticker instance that can be cleanly shutdown
//
// expireEphemeralNodes deletes ephemeral machine records that have not been
// seen for longer than h.cfg.EphemeralNodeInactivityTimeout.
func (h *Headscale) expireEphemeralNodesPatch(milliSeconds int64) *time.Ticker {
	ticker := time.NewTicker(time.Duration(milliSeconds) * time.Millisecond)
	go func() {
		for range ticker.C {
			h.expireEphemeralNodesWorker()
		}
	}()

	return ticker
}
