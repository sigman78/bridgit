package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sigman78/bridgit/internal/app"
	"github.com/sigman78/bridgit/internal/config"
	"github.com/sigman78/bridgit/internal/samlidp"
	"github.com/sigman78/bridgit/internal/signing"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "metadata" {
		if err := runMetadata(os.LookupEnv, os.Stdout); err != nil {
			slog.Error("metadata generation failed", "error", err)
			os.Exit(1)
		}
		return
	}
	os.Exit(run())
}

func runMetadata(lookup config.LookupEnv, output io.Writer) error {
	publicURLValue, ok := lookup("BRIDGIT_PUBLIC_URL")
	if !ok {
		return errors.New("BRIDGIT_PUBLIC_URL is required")
	}
	publicURL, err := url.Parse(strings.TrimSpace(publicURLValue))
	if err != nil || publicURL.Scheme != "https" || publicURL.Host == "" || publicURL.Path != "" || publicURL.RawQuery != "" || publicURL.Fragment != "" || publicURL.User != nil {
		return errors.New("BRIDGIT_PUBLIC_URL must be an HTTPS origin")
	}
	certificateFile, ok := lookup("BRIDGIT_SAML_CERT_FILE")
	if !ok || strings.TrimSpace(certificateFile) == "" {
		return errors.New("BRIDGIT_SAML_CERT_FILE is required")
	}
	keyFile, ok := lookup("BRIDGIT_SAML_KEY_FILE")
	if !ok || strings.TrimSpace(keyFile) == "" {
		return errors.New("BRIDGIT_SAML_KEY_FILE is required")
	}
	key, certificate, err := signing.Load(strings.TrimSpace(certificateFile), strings.TrimSpace(keyFile), time.Now())
	if err != nil {
		return err
	}
	provider, err := samlidp.New(samlidp.Config{PublicURL: *publicURL, Key: key, Certificate: certificate})
	if err != nil {
		return err
	}
	metadata, err := provider.MetadataXML()
	if err != nil {
		return err
	}
	if _, err := output.Write(metadata); err != nil {
		return fmt.Errorf("write SAML metadata: %w", err)
	}
	return nil
}

func run() int {
	settings, err := config.Load(os.LookupEnv)
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		return 1
	}
	logger := newLogger(settings.LogLevel)
	slog.SetDefault(logger)

	startupContext, cancelStartup := context.WithTimeout(context.Background(), 15*time.Second)
	handler, err := app.New(startupContext, settings)
	cancelStartup()
	if err != nil {
		logger.Error("startup failed", "error", err)
		return 1
	}

	httpServer := &http.Server{
		Addr:              settings.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	stopContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serveError := make(chan error, 1)
	go func() {
		logger.Info("Bridgit listening", "address", settings.ListenAddr, "public_url", settings.PublicURL.String())
		serveError <- httpServer.ListenAndServe()
	}()

	select {
	case err := <-serveError:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server stopped", "error", err)
			return 1
		}
		return 0
	case <-stopContext.Done():
	}

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()
	if err := httpServer.Shutdown(shutdownContext); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		return 1
	}
	logger.Info("Bridgit stopped")
	return 0
}

func newLogger(level string) *slog.Logger {
	var parsed slog.Level
	switch strings.ToLower(level) {
	case "debug":
		parsed = slog.LevelDebug
	case "warn":
		parsed = slog.LevelWarn
	case "error":
		parsed = slog.LevelError
	default:
		parsed = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parsed}))
}
