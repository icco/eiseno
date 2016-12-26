package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/gin-contrib/sessions"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gopkg.in/gin-gonic/gin.v1"
	"gopkg.in/pg.v5"
	"gopkg.in/pg.v5/orm"
)

// Credentials which stores google ids.
type GoogleCredentials struct {
	Cid     string `json:"cid"`
	Csecret string `json:"csecret"`
}

type Credential struct {
	Id        string `json:"id"`
	UserId    int64
	Secret    string `sql:"-"`
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
	Id          int64
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

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func init() {
	file, err := ioutil.ReadFile("./creds.json")
	if err != nil {
		if os.IsNotExist(err) {
			cred = GoogleCredentials{
				Cid:     os.Getenv("GoogleCid"),
				Csecret: os.Getenv("GoogleCsecret"),
			}
		} else {
			log.Printf("File error: %v\n", err)
			os.Exit(1)
		}
	} else {
		json.Unmarshal(file, &cred)
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

	dbOpts = &pg.Options{
		User:     "postgres",
		Database: "eiseno",
	}

	// If on heroku, set some things
	if os.Getenv("GIN_MODE") == "release" {
		oauthConf.RedirectURL = "https://onesie.website/auth"

		u, err := url.Parse(os.Getenv("DATABASE_URL"))
		if err != nil {
			log.Fatal(err)
		}

		dbOpts.User = u.User.Username()
		dbOpts.Password, _ = u.User.Password()
		dbOpts.Addr = u.Host
		dbOpts.Database = u.Path
	}

	db := pg.Connect(dbOpts)
	err = createSchema(db)
	if err != nil {
		panic(err)
	}
}

func createSchema(db *pg.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (id serial, email text)`,
		`CREATE TABLE IF NOT EXISTS sites (id serial, domain text, user_id bigint, ssl boolean, dns boolean)`,
		`CREATE EXTENSION IF NOT EXISTS pgcrypto`,
		`CREATE TABLE IF NOT EXISTS credentials (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), secret_enc text, user_id bigint)`,
	}
	for _, q := range queries {
		_, err := db.Exec(q)
		if err != nil {
			return err
		}
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
	email, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}
	defer email.Body.Close()
	data, err := ioutil.ReadAll(email.Body)
	if err != nil {
		panic(err)
	}
	log.Println("data: ", string(data))

	var user *User
	err = json.Unmarshal(data, &user)
	if err != nil {
		panic(err)
	}

	db := pg.Connect(dbOpts)
	_, err = db.Model(user).
		Column("id").
		Where("email = ?email").
		Returning("id").
		SelectOrInsert()
	if err != nil {
		panic(err)
	}

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

	if user_id < 1 {
		c.Redirect(http.StatusFound, "/")
		return
	}

	db := pg.Connect(dbOpts)
	user := User{
		Id: user_id,
	}
	err := db.Model(&user).Column("user.*", "Sites", "Credentials").First()
	if err != nil {
		panic(err)
	}

	if len(user.Credentials) == 0 {
		err = user.GenerateCred()
		if err != nil {
			panic(err)
		}
	}

	c.HTML(http.StatusOK, "home.html", gin.H{
		"user": user,
	})
}

func uploadHandler(c *gin.Context) {
	// Get Headers, validate

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
		panic(err)
	}

	site := Site{
		Domain: c.PostForm("domain"),
		UserId: user.Id,
		Ssl:    false,
		Dns:    false,
	}
	err = db.Insert(&site)
	if err != nil {
		panic(err)
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

func main() {
	router := gin.Default()
	router.Use(sessions.Sessions("eiseno_session", store))
	router.Static("/css", "./static/css")
	router.Static("/img", "./static/img")
	router.LoadHTMLGlob("templates/*")

	router.GET("/", indexHandler)
	router.GET("/login", loginHandler)
	router.GET("/auth", authHandler)
	router.GET("/home", homeHandler)
	router.POST("/sites", siteHandler)

	port := "9090"
	if os.Getenv("PORT") != "" {
		port = os.Getenv("PORT")
	}

	router.Run(fmt.Sprintf(":%s", port))
}
