package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"mime"
	"net/http"
	stdmail "net/mail"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jacksongrow0/SimpleSCEP/internal/acme"
	"github.com/jacksongrow0/SimpleSCEP/internal/audit"
	"github.com/jacksongrow0/SimpleSCEP/internal/auth"
	"github.com/jacksongrow0/SimpleSCEP/internal/clientip"
	"github.com/jacksongrow0/SimpleSCEP/internal/database"
	"github.com/jacksongrow0/SimpleSCEP/internal/est"
	"github.com/jacksongrow0/SimpleSCEP/internal/home"
	"github.com/jacksongrow0/SimpleSCEP/internal/mail"
	"github.com/jacksongrow0/SimpleSCEP/internal/mailpreview"
	"github.com/jacksongrow0/SimpleSCEP/internal/middleware"
	"github.com/jacksongrow0/SimpleSCEP/internal/pki"
	"github.com/jacksongrow0/SimpleSCEP/internal/resend"
	"github.com/jacksongrow0/SimpleSCEP/internal/scep"
)

type logSender struct{}

func (logSender) Send(_ context.Context, msg mail.Message) error {
	log.Printf("email example: to=%q subject=%q body=%q", msg.To, msg.Subject, msg.Body)
	return nil
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve":
			serve()
		case "jet":
			database.GenerateJet()
		case "mailpreview":
			mailpreview.Run()
		default:
			log.Fatalf("unknown command %q", os.Args[1])
		}
		return
	}

	database.Migrations()
	watch()
}

func watch() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	views := exec.CommandContext(ctx,
		"go", "tool", "templ", "generate",
		"-watch",
		"-watch-pattern", `(.+\.go$)|(.+\.templ$)|(.+_templ\.txt$)|(^input\.css$)`,
		"-cmd", "npm run dev:server",
		"-proxy", "http://localhost:8080",
		"-proxyport", "3000",
		"-open-browser=false",
	)
	views.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	views.Stdout, views.Stderr, views.Stdin = os.Stdout, os.Stderr, os.Stdin
	if err := views.Start(); err != nil {
		log.Fatal("start Templ watcher: ", err)
	}

	done := make(chan error, 1)
	go func() { done <- views.Wait() }()
	var err error
	interrupted := false
	select {
	case <-ctx.Done():
		interrupted = true
	case err = <-done:
	}
	terminate(views)
	stop()
	if interrupted {
		<-done
		return
	}
	if err != nil {
		log.Fatal("Templ watcher: ", err)
	}
	log.Fatal("Templ watcher exited unexpectedly")
}

func terminate(commands ...*exec.Cmd) {
	for _, command := range commands {
		if command.Process != nil {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		}
	}
}

// developmentHost reports whether a host names this machine rather than a
// deployment. It gates the one place where a missing mail provider is tolerated,
// so it is deliberately a short allow list: anything it does not recognise is
// treated as production, which fails closed at startup rather than silently
// shipping login links to a log file.
//
// The reserved suffixes are the ones RFC 6761 and RFC 6762 set aside for exactly
// this — .test for testing, .localhost for loopback, .local for mDNS — so a
// developer using vpn.test or simplescep.localhost is covered without anyone
// having to add a variable for it.
// publicFile serves one file out of public/ at a fixed path.
//
// http.ServeFile rather than a FileServer rooted at public/: a directory server
// at "/" would answer every unmatched path, and this mux's "/" is the signed-in
// overview. Naming the files that are served is also what keeps public/ from
// becoming a way to publish anything dropped into it.
func publicFile(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join("public", filepath.Base(name)))
	})
}

func developmentHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	switch host {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	for _, suffix := range []string{".localhost", ".test", ".local"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// minAuthSecretLen is the floor for AUTH_SECRET, which is the HMAC key for the
// session cookie: forging it forges any session, and an administrator session
// can destroy CA key versions. 32 characters is what `openssl rand -base64 32`
// produces and well past what an offline search could reach.
const minAuthSecretLen = 32

// bootstrapSetupToken decides whether this deployment still needs its
// singleton organization created, and if so, mints the one-time token
// POST /setup requires and prints the URL to reach it.
//
// This is a self-hosted, single-organization application: once an
// organization exists, /setup has nothing left to do and this returns "" —
// the empty string is itself the refusal, since Handler.validSetupToken
// never matches an empty token.
func bootstrapSetupToken(ctx context.Context, repo auth.Repository, appURL string) string {
	var exists bool
	if err := repo.AuthFlow(ctx, func(ctx context.Context) error {
		var err error
		exists, err = repo.OrganizationExists(ctx)
		return err
	}); err != nil {
		log.Fatalf("could not check whether this instance is already set up: %v", err)
	}
	if exists {
		return ""
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		log.Fatalf("could not generate a setup token: %v", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	log.Printf("this instance is not yet set up — visit %s/setup?token=%s to create the administrator account",
		strings.TrimRight(appURL, "/"), token)
	return token
}

func serve() {
	// This process keeps its own clock in UTC, to match the one the database
	// keeps.
	//
	// Almost every timestamp column in this schema is `timestamp without time
	// zone`, and pgx encodes a time.Time into one by discarding the zone and
	// keeping the wall clock — 16:25 EDT is stored as 16:25, not as 20:25.
	// database.postgresURL pins the connection to UTC and database.AssertUTC
	// refuses to start without it, so the queries reading those columns compare
	// against LOCALTIMESTAMP in UTC. Both halves are needed: with only the
	// database pinned, a process running anywhere west of Greenwich writes
	// expiries that are already hours in the past, and every sign-in link is
	// refused as expired the moment it is issued. East of Greenwich the same
	// mismatch keeps sessions alive hours past their expiry instead, which is the
	// same bug wearing the costume of a security hole.
	//
	// Containers already run UTC, so this changes nothing in production; what it
	// fixes is a developer's machine, where the failure looks like login being
	// broken and nothing in a log says why.
	time.Local = time.UTC

	// APP_URL is validated before anything consumes it: auth builds emailed
	// magic links from it, and those must never fall back to request headers.
	// It is read this early because three separate gates key off whether it
	// names a developer's machine — the sslmode floor immediately below, the
	// mail sender, and the key provider — and the first of those runs before
	// the process has opened a connection.
	appURL := os.Getenv("APP_URL")
	parsedAppURL, err := url.Parse(appURL)
	if err != nil || (parsedAppURL.Scheme != "http" && parsedAppURL.Scheme != "https") || parsedAppURL.Host == "" {
		log.Fatal("valid APP_URL is required")
	}

	// Before the first connection, because the first connection is a migration
	// run that would otherwise carry the password over plaintext to say so.
	if err := database.AssertSSLMode(developmentHost(parsedAppURL.Hostname())); err != nil {
		log.Fatal(err)
	}

	database.Migrations()

	// Cancelled on SIGTERM, which is what a container runtime sends before it
	// kills the process. Everything with a lifetime longer than a request takes
	// this context, so a deploy stops the workers between units of work rather
	// than in the middle of one — a CRL publication or an Intune revocation
	// sweep interrupted partway leaves a transaction to roll back and a customer
	// wondering why their revocation did not land.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := database.OpenDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Tenant isolation rests on row level security, and a superuser connection or
	// one forgotten ALTER TABLE would disable it silently. Checked here so that
	// fails at startup rather than as a customer reading another's certificates.
	if err := database.AssertRLSEnforced(context.Background(), db); err != nil {
		log.Fatal(err)
	}
	// Checked here for the same reason: an expiry that is silently four hours
	// long is not something a request will report.
	if err := database.AssertUTC(context.Background(), db); err != nil {
		log.Fatal(err)
	}

	sender := mail.Sender(logSender{})
	if key := os.Getenv("RESEND_API_KEY"); key != "" {
		from := strings.TrimSpace(os.Getenv("MAIL_FROM"))
		if from == "" {
			log.Fatal("MAIL_FROM is required when RESEND_API_KEY is configured")
		}
		if _, err := stdmail.ParseAddress(from); err != nil {
			log.Fatalf("MAIL_FROM must be a valid email address: %v", err)
		}
		sender = resend.NewSender(key, from)
	} else if !developmentHost(parsedAppURL.Hostname()) {
		log.Fatalf("RESEND_API_KEY is required when APP_URL is %q: without it login links are written to the log instead of sent, and no one can sign in", appURL)
	}
	if replyTo := strings.TrimSpace(os.Getenv("MAIL_REPLY_TO")); replyTo != "" {
		if _, err := stdmail.ParseAddress(replyTo); err != nil {
			log.Fatalf("MAIL_REPLY_TO must be a valid email address: %v", err)
		}
	}
	authSecret := os.Getenv("AUTH_SECRET")
	if len(authSecret) < minAuthSecretLen {
		log.Fatalf("AUTH_SECRET must be at least %d characters; generate one with: openssl rand -base64 32", minAuthSecretLen)
	}
	// Decided before any request is served: ClientIP and the EST HTTPS check both
	// ask this package which forwarded headers to believe, and a deployment that
	// answered "all of them" would hand every caller a forgeable rate-limit key.
	if err := clientip.ConfigureTrustedProxies(os.Getenv("TRUSTED_PROXY_CIDRS")); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	// public/ is the brand: the logos the pages render, the favicons and the web
	// manifest. It is committed rather than generated, which is what separates it
	// from static/ — that directory is Tailwind output and copied node_modules,
	// rebuilt at every deploy and gitignored, and nothing hand-placed in it
	// survives. Anything a designer hands over belongs here.
	// Go's table has no entry for .webmanifest, so the file would be served as
	// text/plain and Chrome would decline to install anything from it.
	if err := mime.AddExtensionType(".webmanifest", "application/manifest+json"); err != nil {
		log.Fatal(err)
	}
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("public/assets"))))
	// The two files a browser and a crawler ask for by fixed name, at the root
	// because that is the only place either looks for them. Everything else the
	// brand ships is reached through /assets/ above.
	for _, file := range []string{"/favicon.ico", "/robots.txt"} {
		mux.Handle("GET "+file, publicFile(file))
	}
	// The platform's liveness probe. It reports on the database because that is
	// the dependency whose loss makes every page fail; the key provider is
	// checked once at startup instead, since a probe that called KMS on every
	// poll would bill for the privilege and rate-limit itself.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		pingCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := db.PingContext(pingCtx); err != nil {
			log.Printf("health check failed: %v", err)
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok"))
	})
	mailService := mail.NewService(sender)
	authRepo := auth.NewRepository(db)
	setupToken := bootstrapSetupToken(ctx, authRepo, appURL)
	// Budgets for the unauthenticated surface, per minute per key. The login pair
	// is asymmetric on purpose: ten attempts from one address covers a person
	// retyping a typo, while three sends to any one mailbox is well above honest
	// use and well below what makes an inbox unusable.
	authLimits := auth.Limits{
		LoginIP:    middleware.NewRateLimiter(10),
		LoginEmail: middleware.NewRateLimiter(3),
		Signup:     middleware.NewRateLimiter(5),
		Redeem:     middleware.NewRateLimiter(20),
		StepUp:     middleware.NewRateLimiter(5),
	}
	// Constructed before the auth handler, which now needs it: the TOTP secret is
	// sealed by the same provider that protects SCEP RA keys and ACME EAB keys.
	pkiProvider, closeProvider := keyProvider(parsedAppURL.Hostname())
	defer closeProvider()
	if err := pkiProvider.HealthCheck(context.Background()); err != nil {
		log.Fatalf("key provider health check failed: %v", err)
	}
	// Passkeys are optional: TOTP is the mandatory factor and does not depend on
	// this. A configuration that cannot yield a relying-party id leaves them
	// unavailable and logs why, rather than refusing to start — the RP id is
	// derived from APP_URL, which is already validated above, so reaching this is
	// a passkey scope that does not match the host, and nothing else.
	webAuthn, err := auth.NewWebAuthn(appURL)
	if err != nil {
		log.Fatalf("passkey configuration is invalid: %v", err)
	}
	auth.NewHandler(authRepo, mailService, authSecret, appURL,
		audit.NewRepository(db), authLimits, pkiProvider, webAuthn, setupToken).RegisterRoutes(mux)
	// One operator-managed multi-tenant Entra application serves connected
	// directories; blank credentials leave the Intune connector disabled.
	intuneApp := scep.IntuneApp{
		ClientID:     os.Getenv("INTUNE_APP_CLIENT_ID"),
		ClientSecret: os.Getenv("INTUNE_APP_CLIENT_SECRET"),
	}
	if !intuneApp.Deployed() {
		log.Println("INTUNE_APP_CLIENT_ID/INTUNE_APP_CLIENT_SECRET unset: the Microsoft Intune connector is disabled")
	}
	pki.NewHandlerWithURL(db, pkiProvider, appURL).RegisterRoutes(mux)
	scep.RegisterRoutes(mux, db, pkiProvider, appURL, intuneApp, authSecret)
	acme.RegisterRoutes(mux, db, pkiProvider, appURL)
	// EST needs no background worker: it holds no orders to expire and no nonces
	// to collect, so nothing outlives a request.
	est.RegisterRoutes(mux, db, pkiProvider, appURL)
	// Waited on at shutdown rather than abandoned: each of these holds a database
	// transaction while it works, and a process that exits underneath one leaves
	// the connection for Postgres to time out.
	var workers sync.WaitGroup
	for _, worker := range []func(context.Context){
		func(ctx context.Context) { scep.RunIntuneRevocations(ctx, db, pkiProvider, appURL, intuneApp) },
		func(ctx context.Context) { pki.RunCRLRenewal(ctx, db, pkiProvider, appURL) },
		func(ctx context.Context) { acme.RunOrderExpiry(ctx, db) },
		func(ctx context.Context) { pki.RunExpiryAlerts(ctx, db, mailService, appURL) },
	} {
		workers.Add(1)
		go func() {
			defer workers.Done()
			worker(ctx)
		}()
	}
	// Registered last: home owns the catch-all "GET /", which would otherwise
	// shadow every protocol route above it.
	home.RegisterRoutes(mux, db, appURL)

	log.Println("server listening on http://localhost:8080")
	// Outermost first. Recover wraps everything so the deferred rollback inside
	// Auth runs as the stack unwinds. CSRF sits outside Auth so a refused
	// cross-origin request never opens a database transaction.
	// StepUp sits inside Auth because it needs the session, and outside the mux
	// because resolving the route pattern is what lets a test check that every
	// guarded pattern still exists.
	// Flash sits inside CSRF so a refused cross-origin request never consumes a
	// pending toast, and outside the mux because the static file server lives
	// inside it — see the guard in middleware.Flash for why that matters.
	handler := middleware.Recover(
		middleware.SecurityHeaders(
			middleware.CSRF(appURL,
				middleware.Flash(authSecret,
					middleware.Auth(db, authRepo, authSecret,
						middleware.StepUp(mux, mux))))))
	server := &http.Server{
		Addr:              ":8080",
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	listenErr := make(chan error, 1)
	go func() {
		// ErrServerClosed is what Shutdown causes and is not a failure.
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			listenErr <- err
			return
		}
		close(listenErr)
	}()

	select {
	case err := <-listenErr:
		if err != nil {
			log.Fatal(err)
		}
		return
	case <-ctx.Done():
	}

	// Stop translating signals now, so a second SIGTERM from an impatient
	// orchestrator kills the process outright rather than being swallowed while
	// this waits.
	stop()
	log.Println("shutting down")

	// Longer than the 30s WriteTimeout, so an in-flight request is bounded by its
	// own timeout rather than cut off by this one. A SCEP enrollment interrupted
	// mid-issuance is the case worth avoiding: the certificate is signed and
	// recorded but the device never receives it, and the device retries into a
	// duplicate.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed, closing: %v", err)
		_ = server.Close()
	}
	workers.Wait()
	log.Println("stopped")
}

func keyProvider(appHost string) (pki.KeyProvider, func()) {
	switch pki.KeyProviderName() {
	case pki.KeyProviderLocal:
		// Gated on the same allow list as the mail sender, and for a stronger
		// reason. FakeProvider signs with keys held in process memory and mints a
		// fresh protection key at every start — and that key is what seals every
		// TOTP secret, every SCEP RA private key and every ACME EAB MAC key
		// already in the database. So a deployment that reached this by accident
		// would not merely lose its CAs on the next restart: it would make every
		// stored second factor undecryptable, locking every user out of their own
		// account, while reporting itself healthy the whole time.
		//
		// KeyProviderSummary says "In-memory" in the UI, but that is a string on a
		// page nobody reads twice. This is the check.
		if !developmentHost(appHost) {
			log.Fatalf("KEY_PROVIDER=local is refused when APP_URL names %q: it signs with "+
				"in-memory keys and reseals every TOTP secret, SCEP RA key and ACME EAB key "+
				"under a protection key that is discarded at exit. Use google or azure", appHost)
		}
		log.Println("WARNING: KEY_PROVIDER=local is deprecated: in-memory software CA keys are lost on restart")
		return pki.NewLocalProvider(), func() {}
	case pki.KeyProviderGoogle:
		keyRing := strings.TrimSpace(os.Getenv("GOOGLE_CLOUD_KMS_KEY_RING"))
		protectionKey := strings.TrimSpace(os.Getenv("GOOGLE_CLOUD_KMS_PROTECTION_KEY"))
		if keyRing == "" {
			log.Fatal("KEY_PROVIDER=google requires GOOGLE_CLOUD_KMS_KEY_RING")
		}
		if protectionKey == "" {
			log.Fatal("KEY_PROVIDER=google requires GOOGLE_CLOUD_KMS_PROTECTION_KEY")
		}
		provider, err := pki.NewCloudKMSProvider(context.Background(), keyRing, protectionKey)
		if err != nil {
			log.Fatal(err)
		}
		log.Print("key provider: Google Cloud KMS (CA protection selected per CA)")
		return provider, func() { _ = provider.Close() }
	case pki.KeyProviderAzure:
		vaultURL := strings.TrimSpace(os.Getenv("AZURE_KEY_VAULT_URL"))
		protectionKey := strings.TrimSpace(os.Getenv("AZURE_KEY_VAULT_PROTECTION_KEY"))
		if vaultURL == "" {
			log.Fatal("KEY_PROVIDER=azure requires AZURE_KEY_VAULT_URL")
		}
		if protectionKey == "" {
			log.Fatal("KEY_PROVIDER=azure requires AZURE_KEY_VAULT_PROTECTION_KEY")
		}
		provider, err := pki.NewAzureKeyVaultProvider(vaultURL, protectionKey)
		if err != nil {
			log.Fatal(err)
		}
		log.Print("key provider: Azure Key Vault (CA protection selected per CA)")
		return provider, func() {}
	default:
		log.Fatalf("unknown KEY_PROVIDER %q (use google, azure, or deprecated local development mode)", pki.KeyProviderName())
		return nil, func() {}
	}
}
