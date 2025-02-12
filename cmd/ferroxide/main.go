package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	imapserver "github.com/emersion/go-imap/server"
	"github.com/emersion/go-mbox"
	"github.com/emersion/go-smtp"
	"golang.org/x/term"

	"github.com/acheong08/ferroxide/auth"
	"github.com/acheong08/ferroxide/caldav"
	"github.com/acheong08/ferroxide/carddav"
	"github.com/acheong08/ferroxide/config"
	"github.com/acheong08/ferroxide/events"
	"github.com/acheong08/ferroxide/exports"
	imapbackend "github.com/acheong08/ferroxide/imap"
	"github.com/acheong08/ferroxide/imports"
	"github.com/acheong08/ferroxide/protonmail"
	smtpbackend "github.com/acheong08/ferroxide/smtp"
	"github.com/google/uuid"
)

const (
	defaultAPIEndpoint = "https://mail.proton.me/api"
	torAPIEndpoint     = "https://mail.protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion/api"
	defaultAppVersion  = "Other"
)

var (
	debug       bool
	apiEndpoint string
	appVersion  string
	proxyURL    string
	tor         bool
)

func makeHTTPClientFromProxy(proxyArg string) (*http.Client, error) {
	fmtProxy := ""
	client := &http.Client{}
	if tor {
		un, err := uuid.NewRandom()
		if err != nil {
			return nil, err
		}
		// Tor requires socks5. To keep the same format as without tor, we allow
		// the user to specify socks5:// in the proxy URL.
		// But we remove it
		if strings.HasPrefix(proxyArg, "socks5://") {
			proxyArg = strings.Replace(proxyArg, "socks5://", "", 1)
		}
		fmtProxy = fmt.Sprintf("socks5://ferroxide_%s::@%s", un, proxyArg)

	} else {
		if !strings.Contains(proxyArg, "://") {
			// Assume socks5:// if no scheme is provided
			proxyArg = "socks5://" + proxyArg
		}
		fmtProxy = proxyArg // Don't hard code socks5://
	}

	proxy, err := url.Parse(fmtProxy)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		Proxy: http.ProxyURL(proxy),
	}

	client = &http.Client{Transport: tr}
	return client, nil
}
func newClient() *protonmail.Client {
	httpClient := &http.Client{}
	if proxyURL != "" {
		proxiedClient, err := makeHTTPClientFromProxy(proxyURL)
		if err != nil {
			log.Fatal("Error creating proxied http.Client: ", err)
		}

		httpClient = proxiedClient
	}
	return &protonmail.Client{
		RootURL:    apiEndpoint,
		AppVersion: appVersion,
		Debug:      debug,
		HTTPClient: httpClient,
	}
}

func askPass(prompt string) ([]byte, error) {
	f := os.Stdin
	if !term.IsTerminal(int(f.Fd())) {
		// This can happen if stdin is used for piping data
		// TODO: the following assumes Unix
		var err error
		if f, err = os.Open("/dev/tty"); err != nil {
			return nil, err
		}
		defer f.Close()
	}
	fmt.Fprintf(os.Stderr, "%v: ", prompt)
	b, err := term.ReadPassword(int(f.Fd()))
	if err == nil {
		fmt.Fprintf(os.Stderr, "\n")
	}
	return b, err
}

func askBridgePass() (string, error) {
	if v := os.Getenv("HYDROXIDE_BRIDGE_PASS"); v != "" {
		return v, nil
	}
	b, err := askPass("Bridge password")
	return string(b), err
}

func listenAndServeSMTP(addr string, debug bool, authManager *auth.Manager, tlsConfig *tls.Config) error {
	be := smtpbackend.New(authManager)
	s := smtp.NewServer(be)
	s.Addr = addr
	s.Domain = "localhost" // TODO: make this configurable
	s.AllowInsecureAuth = tlsConfig == nil
	s.TLSConfig = tlsConfig
	if debug {
		s.Debug = os.Stdout
	}

	if s.TLSConfig != nil {
		log.Println("SMTP server listening with TLS on", s.Addr)
		return s.ListenAndServeTLS()
	}

	log.Println("SMTP server listening on", s.Addr)
	return s.ListenAndServe()
}

func listenAndServeIMAP(addr string, debug bool, authManager *auth.Manager, eventsManager *events.Manager, tlsConfig *tls.Config) error {
	be := imapbackend.New(authManager, eventsManager)
	s := imapserver.New(be)
	s.Addr = addr
	s.AllowInsecureAuth = tlsConfig == nil
	s.TLSConfig = tlsConfig
	if debug {
		s.Debug = os.Stdout
	}

	if s.TLSConfig != nil {
		log.Println("IMAP server listening with TLS on", s.Addr)
		return s.ListenAndServeTLS()
	}

	log.Println("IMAP server listening on", s.Addr)
	return s.ListenAndServe()
}

func listenAndServeCalDAV(addr string, authManager *auth.Manager, eventsManager *events.Manager, tlsConfig *tls.Config) error {
	handlers := make(map[string]http.Handler)

	s := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			resp.Header().Set("WWW-Authenticate", "Basic")

			username, password, ok := req.BasicAuth()
			if !ok {
				resp.WriteHeader(http.StatusUnauthorized)
				io.WriteString(resp, "Credentials are required")
				return
			}

			c, privateKeys, err := authManager.Auth(username, password)
			if err != nil {
				if err == auth.ErrUnauthorized {
					resp.WriteHeader(http.StatusUnauthorized)
				} else {
					resp.WriteHeader(http.StatusInternalServerError)
				}
				io.WriteString(resp, err.Error())
				return
			}

			h, ok := handlers[username]
			if !ok {
				ch := make(chan *protonmail.Event)
				eventsManager.Register(c, username, ch, nil)
				h = caldav.NewHandler(c, privateKeys, username, ch)

				handlers[username] = h
			}

			h.ServeHTTP(resp, req)
		}),
	}

	log.Println("CalDAV server listening on", s.Addr)
	return s.ListenAndServe()
}

func listenAndServeCardDAV(addr string, authManager *auth.Manager, eventsManager *events.Manager, tlsConfig *tls.Config) error {
	handlers := make(map[string]http.Handler)

	s := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			resp.Header().Set("WWW-Authenticate", "Basic")

			username, password, ok := req.BasicAuth()
			if !ok {
				resp.WriteHeader(http.StatusUnauthorized)
				io.WriteString(resp, "Credentials are required")
				return
			}

			c, privateKeys, err := authManager.Auth(username, password)
			if err != nil {
				if err == auth.ErrUnauthorized {
					resp.WriteHeader(http.StatusUnauthorized)
				} else {
					resp.WriteHeader(http.StatusInternalServerError)
				}
				io.WriteString(resp, err.Error())
				return
			}

			h, ok := handlers[username]
			if !ok {
				ch := make(chan *protonmail.Event)
				eventsManager.Register(c, username, ch, nil)
				h = carddav.NewHandler(c, privateKeys, ch)

				handlers[username] = h
			}

			h.ServeHTTP(resp, req)
		}),
	}

	if s.TLSConfig != nil {
		log.Println("CardDAV server listening with TLS on", s.Addr)
		return s.ListenAndServeTLS("", "")
	}

	log.Println("CardDAV server listening on", s.Addr)
	return s.ListenAndServe()
}

func isMbox(br *bufio.Reader) (bool, error) {
	prefix := []byte("From ")
	b, err := br.Peek(len(prefix))
	if err != nil {
		return false, err
	}
	return bytes.Equal(b, prefix), nil
}

const usage = `usage: ferroxide [options...] <command>
Commands:
	auth <username>		Login to ProtonMail via ferroxide
	carddav			Run ferroxide as a CardDAV server
	caldav			Run ferroxide as a CalDAV server
	export-secret-keys <username> Export secret keys
	imap			Run ferroxide as an IMAP server
	import-messages <username> [file]	Import messages
	export-messages [options...] <username>	Export messages
	sendmail <username> -- <args...>	sendmail(1) interface
	serve			Run all servers
	smtp			Run ferroxide as an SMTP server
	status			View ferroxide status

Environment variables:
	HYDROXIDE_BRIDGE_PASS	Don't prompt for the bridge password, use this variable instead

`

func main() {
	flag.BoolVar(&debug, "debug", false, "Enable debug logs")
	flag.StringVar(&apiEndpoint, "api-endpoint", defaultAPIEndpoint, "ProtonMail API endpoint")
	flag.StringVar(&appVersion, "app-version", defaultAppVersion, "ProtonMail app version")

	smtpHost := flag.String("smtp-host", "127.0.0.1", "Allowed SMTP email hostname on which ferroxide listens, defaults to 127.0.0.1")
	smtpPort := flag.String("smtp-port", "1025", "SMTP port on which ferroxide listens, defaults to 1025")
	disableSMTP := flag.Bool("disable-smtp", false, "Disable SMTP for ferroxide serve")

	imapHost := flag.String("imap-host", "127.0.0.1", "Allowed IMAP email hostname on which ferroxide listens, defaults to 127.0.0.1")
	imapPort := flag.String("imap-port", "1143", "IMAP port on which ferroxide listens, defaults to 1143")
	disableIMAP := flag.Bool("disable-imap", false, "Disable IMAP for ferroxide serve")

	carddavHost := flag.String("carddav-host", "127.0.0.1", "Allowed CardDAV email hostname on which ferroxide listens, defaults to 127.0.0.1")
	carddavPort := flag.String("carddav-port", "8080", "CardDAV port on which ferroxide listens, defaults to 8080")
	disableCardDAV := flag.Bool("disable-carddav", false, "Disable CardDAV for ferroxide serve")

	caldavHost := flag.String("caldav-host", "127.0.0.1", "Allowed CalDAV email hostname on which ferroxide listens, defaults to 127.0.0.1")
	caldavPort := flag.String("caldav-port", "8081", "CalDAV port on which ferroxide listens, defaults to 8081")
	disableCalDAV := flag.Bool("disable-caldav", false, "Disable CalDAV for ferroxide serve")

	tlsCert := flag.String("tls-cert", "", "Path to the certificate to use for incoming connections")
	tlsCertKey := flag.String("tls-key", "", "Path to the certificate key to use for incoming connections")
	tlsClientCA := flag.String("tls-client-ca", "", "If set, clients must provide a certificate signed by the given CA")

	configHome := flag.String("config-home", "", "Path to the directory where ferroxide stores its configuration")
	flag.StringVar(&proxyURL, "proxy-url", "", "HTTP proxy URL (e.g. socks5://127.0.0.1:1080)")
	flag.BoolVar(&tor, "tor", false, "If set, connect to ProtonMail over Tor")

	authCmd := flag.NewFlagSet("auth", flag.ExitOnError)
	exportSecretKeysCmd := flag.NewFlagSet("export-secret-keys", flag.ExitOnError)
	importMessagesCmd := flag.NewFlagSet("import-messages", flag.ExitOnError)
	exportMessagesCmd := flag.NewFlagSet("export-messages", flag.ExitOnError)
	sendmailCmd := flag.NewFlagSet("sendmail", flag.ExitOnError)

	flag.Usage = func() {
		fmt.Print(usage)
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if tor && proxyURL == "" {
		log.Fatal("Need -proxy to connect to ProtonMail over Tor")
	}

	if tor {
		log.Println("Connecting to ProtonMail over Tor")
		apiEndpoint = torAPIEndpoint
	}

	tlsConfig, err := config.TLS(*tlsCert, *tlsCertKey, *tlsClientCA)
	if err != nil {
		log.Fatal(err)
	}

	if *configHome != "" {
		config.SetConfigHome(*configHome)
	}

	cmd := flag.Arg(0)
	switch cmd {
	case "auth":
		authCmd.Parse(flag.Args()[1:])
		username := authCmd.Arg(0)
		if username == "" {
			log.Fatal("usage: ferroxide auth <username>")
		}

		c := newClient()

		var a *protonmail.Auth
		/*if cachedAuth, ok := auths[username]; ok {
			var err error
			a, err = c.AuthRefresh(a)
			if err != nil {
				// TODO: handle expired token error
				log.Fatal(err)
			}
		}*/

		var loginPassword string
		if a == nil {
			if pass, err := askPass("Password"); err != nil {
				log.Fatal(err)
			} else {
				loginPassword = string(pass)
			}

			authInfo, err := c.AuthInfo(username)
			if err != nil {
				log.Fatal(err)
			}

			a, err = c.Auth(username, loginPassword, authInfo)
			if err != nil {
				log.Fatal(err)
			}

			if a.TwoFactor.Enabled != 0 {
				if a.TwoFactor.TOTP != 1 {
					log.Fatal("Only TOTP is supported as a 2FA method")
				}

				scanner := bufio.NewScanner(os.Stdin)
				fmt.Printf("2FA TOTP code: ")
				scanner.Scan()
				code := scanner.Text()

				scope, err := c.AuthTOTP(code)
				if err != nil {
					log.Fatal(err)
				}
				a.Scope = scope
			}
		}

		var mailboxPassword string
		if a.PasswordMode == protonmail.PasswordSingle {
			mailboxPassword = loginPassword
		}
		if mailboxPassword == "" {
			prompt := "Password"
			if a.PasswordMode == protonmail.PasswordTwo {
				prompt = "Mailbox password"
			}
			if pass, err := askPass(prompt); err != nil {
				log.Fatal(err)
			} else {
				mailboxPassword = string(pass)
			}
		}

		keySalts, err := c.ListKeySalts()
		if err != nil {
			log.Fatal(err)
		}

		_, err = c.Unlock(a, keySalts, mailboxPassword)
		if err != nil {
			log.Fatal(err)
		}

		secretKey, bridgePassword, err := auth.GeneratePassword()
		if err != nil {
			log.Fatal(err)
		}

		err = auth.EncryptAndSave(&auth.CachedAuth{
			Auth:            *a,
			LoginPassword:   loginPassword,
			MailboxPassword: mailboxPassword,
			KeySalts:        keySalts,
		}, username, secretKey)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Bridge password:", bridgePassword)
	case "status":
		usernames, err := auth.ListUsernames()
		if err != nil {
			log.Fatal(err)
		}

		if len(usernames) == 0 {
			fmt.Printf("No logged in user.\n")
		} else {
			fmt.Printf("%v logged in user(s):\n", len(usernames))
			for _, u := range usernames {
				fmt.Printf("- %v\n", u)
			}
		}
	case "export-secret-keys":
		exportSecretKeysCmd.Parse(flag.Args()[1:])
		username := exportSecretKeysCmd.Arg(0)
		if username == "" {
			log.Fatal("usage: ferroxide export-secret-keys <username>")
		}

		bridgePassword, err := askBridgePass()
		if err != nil {
			log.Fatal(err)
		}

		_, privateKeys, err := auth.NewManager(newClient).Auth(username, bridgePassword)
		if err != nil {
			log.Fatal(err)
		}

		wc, err := armor.Encode(os.Stdout, openpgp.PrivateKeyType, nil)
		if err != nil {
			log.Fatal(err)
		}

		for _, key := range privateKeys {
			if err := key.SerializePrivate(wc, nil); err != nil {
				log.Fatal(err)
			}
		}

		if err := wc.Close(); err != nil {
			log.Fatal(err)
		}
	case "import-messages":
		importMessagesCmd.Parse(flag.Args()[1:])
		username := importMessagesCmd.Arg(0)
		archivePath := importMessagesCmd.Arg(1)
		if username == "" {
			log.Fatal("usage: ferroxide import-messages <username> [file]")
		}

		f := os.Stdin
		if archivePath != "" {
			f, err = os.Open(archivePath)
			if err != nil {
				log.Fatal(err)
			}
			defer f.Close()
		}

		bridgePassword, err := askBridgePass()
		if err != nil {
			log.Fatal(err)
		}

		c, _, err := auth.NewManager(newClient).Auth(username, bridgePassword)
		if err != nil {
			log.Fatal(err)
		}

		br := bufio.NewReader(f)
		if ok, err := isMbox(br); err != nil {
			log.Fatal(err)
		} else if ok {
			mr := mbox.NewReader(br)
			for {
				r, err := mr.NextMessage()
				if err == io.EOF {
					break
				} else if err != nil {
					log.Fatal(err)
				}
				if err := imports.ImportMessage(c, r); err != nil {
					log.Fatal(err)
				}
			}
		} else {
			if err := imports.ImportMessage(c, br); err != nil {
				log.Fatal(err)
			}
		}
	case "export-messages":
		// TODO: allow specifying multiple IDs
		var convID, msgID string
		exportMessagesCmd.StringVar(&convID, "conversation-id", "", "conversation ID")
		exportMessagesCmd.StringVar(&msgID, "message-id", "", "message ID")
		exportMessagesCmd.Parse(flag.Args()[1:])
		username := exportMessagesCmd.Arg(0)
		if (convID == "" && msgID == "") || username == "" {
			log.Fatal("usage: ferroxide export-messages [-conversation-id <id>] [-message-id <id>] <username>")
		}

		bridgePassword, err := askBridgePass()
		if err != nil {
			log.Fatal(err)
		}

		c, privateKeys, err := auth.NewManager(newClient).Auth(username, bridgePassword)
		if err != nil {
			log.Fatal(err)
		}

		mboxWriter := mbox.NewWriter(os.Stdout)

		if convID != "" {
			if err := exports.ExportConversationMbox(c, privateKeys, mboxWriter, convID); err != nil {
				log.Fatal(err)
			}
		}
		if msgID != "" {
			if err := exports.ExportMessageMbox(c, privateKeys, mboxWriter, msgID); err != nil {
				log.Fatal(err)
			}
		}

		if err := mboxWriter.Close(); err != nil {
			log.Fatal(err)
		}
	case "smtp":
		addr := *smtpHost + ":" + *smtpPort
		authManager := auth.NewManager(newClient)
		log.Fatal(listenAndServeSMTP(addr, debug, authManager, tlsConfig))
	case "imap":
		addr := *imapHost + ":" + *imapPort
		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()
		log.Fatal(listenAndServeIMAP(addr, debug, authManager, eventsManager, tlsConfig))
	case "caldav":
		addr := *caldavHost + ":" + *caldavPort
		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()
		log.Fatal(listenAndServeCalDAV(addr, authManager, eventsManager, tlsConfig))
	case "carddav":
		addr := *caldavHost + ":" + *caldavPort
		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()
		log.Fatal(listenAndServeCardDAV(addr, authManager, eventsManager, tlsConfig))
	case "serve":
		smtpAddr := *smtpHost + ":" + *smtpPort
		imapAddr := *imapHost + ":" + *imapPort
		carddavAddr := *carddavHost + ":" + *carddavPort
		caldavAddr := *caldavHost + ":" + *caldavPort

		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()

		done := make(chan error, 3)
		if !*disableSMTP {
			go func() {
				done <- listenAndServeSMTP(smtpAddr, debug, authManager, tlsConfig)
			}()
		}
		if !*disableIMAP {
			go func() {
				done <- listenAndServeIMAP(imapAddr, debug, authManager, eventsManager, tlsConfig)
			}()
		}
		if !*disableCardDAV {
			go func() {
				done <- listenAndServeCardDAV(carddavAddr, authManager, eventsManager, tlsConfig)
			}()
		}
		if !*disableCalDAV {
			go func() {
				done <- listenAndServeCalDAV(caldavAddr, authManager, eventsManager, tlsConfig)
			}()
		}
		log.Fatal(<-done)
	case "sendmail":
		username := flag.Arg(1)
		if username == "" || flag.Arg(2) != "--" {
			log.Fatal("usage: ferroxide sendmail <username> -- <args...>")
		}

		// TODO: other sendmail flags
		var dotEOF bool
		sendmailCmd.BoolVar(&dotEOF, "i", false, "don't treat a line with only a . character as the end of input")
		sendmailCmd.Parse(flag.Args()[3:])
		rcpt := sendmailCmd.Args()

		bridgePassword, err := askBridgePass()
		if err != nil {
			log.Fatal(err)
		}

		c, privateKeys, err := auth.NewManager(newClient).Auth(username, bridgePassword)
		if err != nil {
			log.Fatal(err)
		}

		u, err := c.GetCurrentUser()
		if err != nil {
			log.Fatal(err)
		}

		addrs, err := c.ListAddresses()
		if err != nil {
			log.Fatal(err)
		}

		err = smtpbackend.SendMail(c, u, privateKeys, addrs, rcpt, os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Print(usage)
		if cmd != "help" {
			log.Fatal("Unrecognized command")
		}
	}
}
