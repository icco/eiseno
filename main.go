package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cloud.google.com/go/pubsub"
	"cloud.google.com/go/storage"
	"github.com/gin-contrib/sessions"
	"github.com/google/uuid"
	"github.com/mattes/migrate/migrate"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gopkg.in/gin-gonic/gin.v1"
	"gopkg.in/pg.v5"
	"gopkg.in/pg.v5/orm"
	"gopkg.in/unrolled/secure.v1"

	_ "github.com/mattes/migrate/driver/postgres"
)

type ByIP []net.IP

func (s ByIP) Len() int {
	return len(s)
}
func (s ByIP) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s ByIP) Less(i, j int) bool {
	return s[i].String() < s[j].String()
}

// Credentials which stores google ids.
type GoogleCredentials struct {
	Cid     string `json:"cid"`
	Csecret string `json:"csecret"`
}

type Credential struct {
	Id        string `json:"id"`
	UserId    int64  `json:"-"`
	Secret    string `json:"secret"`
	SecretEnc string `json:"-"`
}

func (cred *Credential) IsValidCred() error {
	return bcrypt.CompareHashAndPassword([]byte(cred.SecretEnc), []byte(cred.Secret))
}

func (c *Credential) BeforeInsert(db orm.DB) error {
	enc, err := bcrypt.GenerateFromPassword([]byte(c.Secret), 12)
	c.SecretEnc = string(enc)

	return err
}

// User is a retrieved and authentiacted user.
type User struct {
	Id          int64  `json:"-"`
	Email       string `json:"email"`
	Sites       []*Site
	Credentials []*Credential
}

func (u User) String() string {
	return fmt.Sprintf("User<%d %s>", u.Id, u.Email)
}

func (u *User) GenerateCred() error {
	secret := uuid.New()
	cred := Credential{
		UserId: u.Id,
		Secret: secret.String(),
	}
	db := pg.Connect(dbOpts)
	return db.Insert(&cred)
}

type Site struct {
	Id     int64
	Domain string
	UserId int64
	Dns    bool
	Ssl    bool
}

func (s Site) String() string {
	return fmt.Sprintf("Site<%d %s %v>", s.Id, s.Domain, s.UserId)
}

var cred GoogleCredentials
var dbOpts *pg.Options
var oauthConf *oauth2.Config
var state string
var store = sessions.NewCookieStore([]byte("secret"))
var validIPs = []net.IP{
	net.ParseIP("104.198.128.22"),
	net.ParseIP("104.154.142.2"),
}

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func init() {
	// OAuth Cred Setup
	cred = GoogleCredentials{
		Cid:     os.Getenv("GoogleCid"),
		Csecret: os.Getenv("GoogleCsecret"),
	}

	oauthConf = &oauth2.Config{
		ClientID:     cred.Cid,
		ClientSecret: cred.Csecret,
		RedirectURL:  "http://127.0.0.1:9090/auth",
		// https://developers.google.com/identity/protocols/googlescopes#google_sign-in
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
	log.Print("OAuth Creds setup.")

	// General google server auth needed by pubsub module
	_, err := ioutil.ReadFile(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
	if err != nil {
		if os.IsNotExist(err) {
			json_str := []byte(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON"))
			err := ioutil.WriteFile(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"), json_str, 0777)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
	log.Print("Google Creds Setup.")

	// DB Connection Setup
	dbOpts = &pg.Options{
		User:     "postgres",
		Database: "eiseno",
	}

	// If on heroku, set some things
	if os.Getenv("GIN_MODE") == "release" {
		oauthConf.RedirectURL = "https://www.onesie.website/auth"

		u, err := url.Parse(os.Getenv("DATABASE_URL"))
		if err != nil {
			log.Fatal(err)
		}

		dbOpts.User = u.User.Username()
		dbOpts.Password, _ = u.User.Password()
		dbOpts.Addr = u.Host
		dbOpts.Database = u.Path[1:]
	}

	db := pg.Connect(dbOpts)
	err = createSchema(db)
	if err != nil {
		log.Panicf("Error migrating database: %+v", err)
	}
	log.Print("Database Setup.")
}

func createSchema(db *pg.DB) error {
	userinfo := dbOpts.User
	if dbOpts.Password != "" {
		userinfo = fmt.Sprintf("%s:%s", dbOpts.User, dbOpts.Password)
	}

	opts := ""
	if os.Getenv("GIN_MODE") != "release" {
		opts = "?sslmode=disable"
	}

	dbUrl := fmt.Sprintf("postgres://%s@%s/%s%s", userinfo, dbOpts.Addr, dbOpts.Database, opts)

	allErrors, ok := migrate.UpSync(dbUrl, "./db/migrations")
	if !ok {
		for _, v := range allErrors {
			log.Printf("Migration error: %v\n", v)
		}
		return errors.New("Error running migrations.")
	}

	return nil
}

func indexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{})
}

func getLoginURL(state string) string {
	return oauthConf.AuthCodeURL(state)
}

func authHandler(c *gin.Context) {
	// Handle the exchange code to initiate a transport.
	session := sessions.Default(c)
	retrievedState := session.Get("state")
	if retrievedState != c.Query("state") {
		c.AbortWithError(http.StatusUnauthorized, fmt.Errorf("Invalid session state: %s", retrievedState))
		return
	}

	tok, err := oauthConf.Exchange(oauth2.NoContext, c.Query("code"))
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	client := oauthConf.Client(oauth2.NoContext, tok)
	userdata, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}
	defer userdata.Body.Close()
	data, err := ioutil.ReadAll(userdata.Body)
	if err != nil {
		log.Panicf("Error reading oauth data: %+v", err)
	}
	log.Println("data: ", string(data))

	var user *User
	err = json.Unmarshal(data, &user)
	if err != nil {
		log.Panicf("Error unmarshalling json: %+v", err)
	}

	db := pg.Connect(dbOpts)
	_, err = db.Model(user).
		Column("id").
		Where("email = ?email").
		Returning("id").
		SelectOrInsert()
	if err != nil {
		log.Panicf("Error querying database: %+v", err)
	}

	log.Printf("Logging in user: %d", user.Id)
	session.Set("user_id", user.Id)
	session.Save()

	c.Redirect(http.StatusFound, "/home")
}

func homeHandler(c *gin.Context) {
	session := sessions.Default(c)
	var user_id int64

	// Session data lacks type.
	v := session.Get("user_id")
	if v == nil {
		user_id = 0
	} else {
		user_id = v.(int64)
	}
	log.Printf("Got from session: %+v -> %+v", v, user_id)

	if user_id < 1 {
		c.Redirect(http.StatusFound, "/")
		return
	}

	db := pg.Connect(dbOpts)
	user := User{
		Id: user_id,
	}
	err := db.Select(&user)
	if err != nil {
		log.Panicf("Error querying database: %+v", err)
	}
	err = db.Model(&user).Column("user.*", "Sites", "Credentials").Where("id = ?", user_id).Select()
	if err != nil {
		log.Panicf("Error querying database: %+v", err)
	}

	if len(user.Credentials) == 0 {
		if user.GenerateCred() != nil {
			log.Printf("Error generating user creds: %+v", err)
		}
	}

	log.Printf("Logging in user: %v", user)
	c.HTML(http.StatusOK, "home.html", gin.H{
		"user": user,
	})
}

func uploadHandler(c *gin.Context) {
	keyHdr := http.CanonicalHeaderKey("Onesie-Key")
	secretHdr := http.CanonicalHeaderKey("Onesie-Secret")
	domainHdr := http.CanonicalHeaderKey("Onesie-Domain")

	authKey := c.Request.Header.Get(keyHdr)
	authSecret := c.Request.Header.Get(secretHdr)
	domain := c.Request.Header.Get(domainHdr)
	err := validateAuth(authKey, authSecret, domain)
	if err != nil {
		log.Printf("Error uploading: %+v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}

	// Parse out file
	r := c.Request
	r.ParseMultipartForm(32 << 20)
	file, _, err := r.FormFile("file")
	if err != nil {
		log.Printf("Error parsing: %+v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}
	defer file.Close()

	log.Println("File opened.")

	// Expand into archive
	archive, err := gzip.NewReader(file)
	if err != nil {
		log.Panicf("Error creating gzip reader: %+v", err)
	}
	defer archive.Close()

	// Open google storage client
	client, err := storage.NewClient(c)
	if err != nil {
		log.Panicf("Error connecting to Google Storage: %+v", err)
	}
	bkt := client.Bucket("onesie")

	// Go through file by file
	tarReader := tar.NewReader(archive)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Panicf("Error reading tar: %+v", err)
		}

		path := filepath.Join(domain, header.Name)
		info := header.FileInfo()
		if info.IsDir() {
			continue
		}
		w := bkt.Object(path).NewWriter(c)
		w.ACL = []storage.ACLRule{{Entity: storage.AllUsers, Role: storage.RoleReader}}
		defer w.Close()
		log.Println(path)

		_, err = io.Copy(w, tarReader)
		if err != nil {
			log.Printf("Error writing data to GCS: %+v", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "Success!",
	})
	return
}

// Checks to see if key + secret can upload to domain.
func validateAuth(key string, secret string, domain string) error {
	site := Site{
		Domain: domain,
	}
	cred := Credential{
		Id: key,
	}

	db := pg.Connect(dbOpts)
	err := db.Model(&cred).First()
	if err != nil {
		return err
	}
	err = db.Model(&site).First()
	if err != nil {
		return err
	}

	if site.UserId != cred.UserId {
		return errors.New("Credential not associated with Domain.")
	}

	if cred.Secret != secret {
		return errors.New("Credential secret wrong.")
	}

	return nil
}

func siteHandler(c *gin.Context) {
	session := sessions.Default(c)
	var user_id int64

	// Session data lacks type.
	v := session.Get("user_id")
	if v == nil {
		user_id = 0
	} else {
		user_id = v.(int64)
	}

	if user_id < 1 {
		c.Redirect(http.StatusFound, "/")
		return
	}
	db := pg.Connect(dbOpts)
	user := User{
		Id: user_id,
	}
	err := db.Select(&user)
	if err != nil {
		log.Printf("Error querying database: %+v", err)
	}

	site := Site{
		Domain: strings.TrimSpace(c.PostForm("domain")),
		UserId: user.Id,
		Ssl:    false,
		Dns:    false,
	}
	err = db.Insert(&site)
	if err != nil {
		log.Printf("Error inserting into database: %+v", err)
	}

	c.Redirect(http.StatusFound, "/home")
}

func loginHandler(c *gin.Context) {
	state = randToken()
	session := sessions.Default(c)
	session.Set("state", state)
	session.Save()
	c.Redirect(http.StatusFound, getLoginURL(state))
}

func cronHandler(c *gin.Context) {

	// Write out configs for onesie server.
	go func(c *gin.Context) {
		log.Printf("Spawning Go Routine for Onesie Config Writer.")
		stgClient, err := storage.NewClient(c)
		if err != nil {
			log.Panicf("Error creating storage client: %+v")
		}
		bkt := stgClient.Bucket("onesie-configs")
		dw := bkt.Object("domains.txt").NewWriter(c)
		defer dw.Close()
		hw := bkt.Object("hitch.conf").NewWriter(c)
		defer hw.Close()

		sites := []Site{}
		db := pg.Connect(dbOpts)
		err = db.Model(&sites).Where("dns = true").Order("domain ASC").Select()
		if err != nil {
			log.Printf("Error querying database: %+v", err)
		}

		if _, err := fmt.Fprintf(hw, "frontend = \"[*]:443\"\nciphers  = \"EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH\"\nbackend = \"[::1]:80\"\n\n"); err != nil {
			log.Println(err)
		}
		for _, v := range sites {
			if _, err := fmt.Fprintf(dw, "%s\n", v.Domain); err != nil {
				log.Println(err)
			}

			if _, err := fmt.Fprintf(hw, "pem-file = \"/opt/onesie-configs/hitch/%s.pem\"\n", v.Domain); err != nil {
				log.Println(err)
			}
		}
	}(c)

	// Do DNS Validation
	go func(c *gin.Context) {
		log.Printf("Spawning Go Routine for DNS Validation.")
		sites := []Site{}
		db := pg.Connect(dbOpts)
		err := db.Model(&sites).Order("id ASC").Select()
		if err != nil {
			log.Printf("Error querying database: %+v", err)
		}

		sort.Sort(ByIP(validIPs))
		log.Printf("Valid IPs: %+v", validIPs)

		for _, v := range sites {
			ips, err := net.LookupIP(v.Domain)
			if err != nil {
				log.Println(err)
			}
			sort.Sort(ByIP(ips))
			equal := true
			for i, ip := range ips {
				if !ip.Equal(validIPs[i]) {
					equal = false
				}
			}

			log.Printf("%s: %v: %+v", v.Domain, equal, ips)
			v.Domain = strings.TrimSpace(v.Domain)
			v.Dns = equal
			db.Update(&v)
			if err != nil {
				log.Printf("Error saving to database: %+v", err)
			}
		}
	}(c)

	client, err := pubsub.NewClient(c, "940380154622")
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// The name for the update topic
	topicName := "onesie-updates"
	topic := client.Topic(topicName)
	msgIDs, err := topic.Publish(c, &pubsub.Message{
		Data: []byte("update"),
	})
	if err != nil {
		log.Fatal("Couldn't publish: %+v", err)
	}
	log.Printf("Published a message with a message ID: %s\n", msgIDs[0])
	c.String(http.StatusOK, "OK")
}

func main() {
	secOpts := secure.Options{
		AllowedHosts:         []string{"onesie.website", "www.onesie.website"},
		SSLRedirect:          true,
		SSLHost:              "www.onesie.website",
		SSLProxyHeaders:      map[string]string{"X-Forwarded-Proto": "https"},
		STSSeconds:           315360000,
		STSIncludeSubdomains: true,
		STSPreload:           true,
		FrameDeny:            true,
		ContentTypeNosniff:   true,
		BrowserXssFilter:     true,
		IsDevelopment:        false,
	}

	// Prod Headers
	if os.Getenv("GIN_MODE") != "release" {
		secOpts.IsDevelopment = true

		pg.SetQueryLogger(log.New(os.Stdout, "DB: ", log.LstdFlags))
	}

	secureMiddleware := secure.New(secOpts)
	secureFunc := func() gin.HandlerFunc {
		return func(c *gin.Context) {
			err := secureMiddleware.Process(c.Writer, c.Request)

			// If there was an error, do not continue.
			if err != nil {
				c.Abort()
				return
			}

			// Avoid header rewrite if response is a redirection.
			if status := c.Writer.Status(); status > 300 && status < 399 {
				c.Abort()
			}
		}
	}()

	router := gin.Default()

	router.Use(secureFunc)
	router.Use(sessions.Sessions("eiseno_session", store))

	router.Static("/css", "./static/css")
	router.Static("/img", "./static/img")
	router.LoadHTMLGlob("templates/*")

	router.GET("/", indexHandler)
	router.GET("/login", loginHandler)
	router.GET("/auth", authHandler)
	router.GET("/home", homeHandler)
	router.GET("/cron", cronHandler)

	router.POST("/sites", siteHandler)
	router.POST("/upload", uploadHandler)

	port := "9090"
	if os.Getenv("PORT") != "" {
		port = os.Getenv("PORT")
	}

	router.Run(fmt.Sprintf(":%s", port))
}
