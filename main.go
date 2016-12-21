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

	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gopkg.in/pg.v5"
)

// Credentials which stores google ids.
type Credentials struct {
	Cid     string `json:"cid"`
	Csecret string `json:"csecret"`
}

// User is a retrieved and authentiacted user.
type User struct {
	Id    int64
	Email string `json:"email"`
}

type Site struct {
	Id     int
	Domain string
	User   *User
	Dns    bool
	Ssl    bool
}

func (u User) String() string {
	return fmt.Sprintf("User<%d %s>", u.Id, u.Email)
}

func (s Site) String() string {
	return fmt.Sprintf("Site<%d %s %v>", s.Id, s.Domain, s.User)
}

var cred Credentials
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
			cred = Credentials{
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

	dbOpts := &pg.Options{
		User:     "postgres",
		Database: "eiseno",
	}

	// If on heroku, set some things
	if os.Getenv("GIN_MODE") == "release" {
		oauthConf.RedirectURL = "https://eiseno.herokuapp.com/auth"

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
		`CREATE TABLE IF NOT EXISTS users (id serial, name text, email text)`,
		`CREATE TABLE IF NOT EXISTS sites (id serial, domain text, user_id bigint, ssl boolean, dns boolean)`,
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

	var user User
	err = json.Unmarshal(data, &user)
	if err != nil {
		panic(err)
	}

	db := pg.Connect(dbOpts)
	err = db.Insert(user)
	if err != nil {
		panic(err)
	}

	c.Status(http.StatusOK)
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
	router.Use(sessions.Sessions("goquestsession", store))
	router.Static("/css", "./static/css")
	router.Static("/img", "./static/img")
	router.LoadHTMLGlob("templates/*")

	router.GET("/", indexHandler)
	router.GET("/login", loginHandler)
	router.GET("/auth", authHandler)

	port := "9090"
	if os.Getenv("PORT") != "" {
		port = os.Getenv("PORT")
	}

	router.Run(fmt.Sprintf(":%s", port))
}
