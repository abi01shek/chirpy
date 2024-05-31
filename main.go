package main

import (
	database "chirpy/internal"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

type apiConfig struct {
	FileserverHits int // capitalized because it is exported
	metricsTmpl    string
	DB             *database.DB
	Jwtsecret      string
	Polkakey       string
}

var badWords = [...]string{"kerfuffle", "sharbert", "fornax"}

// healthEndPointHandler: returns a header with 200 value and writes OK to the screen
func healthEndPointHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200) //OK
	_, err := w.Write([]byte("OK"))
	if err != nil {
		fmt.Printf("%v", err)
	}
}

// metricsEndPointHandler: write the current value of file server hits to screen
func (cfg *apiConfig) metricsEndPointHandler(w http.ResponseWriter, r *http.Request) {
	tmplt := template.New(cfg.metricsTmpl)          // create new template
	tmplt, err := tmplt.ParseFiles(cfg.metricsTmpl) // parse html template to create internal representation
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	// cfg.FileserverHits will be filling {{.FileserverHits}} in the template
	err = tmplt.Execute(w, cfg) // fill in the template
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	w.Header().Add("Content-Type", "text/html")
	w.WriteHeader(200) //OK
}

// resetMetricHandler: to reset the hit value
func (cfg *apiConfig) resetMetricHandler(w http.ResponseWriter, r *http.Request) {
	cfg.FileserverHits = 0
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200) //OK
	_, err := w.Write([]byte(fmt.Sprintf("Hits: %d", cfg.FileserverHits)))
	if err != nil {
		fmt.Printf("%v", err)
	}
}

// func middlewareMetricsInc: returns a hanlder function that increments the counter
// and executes the handler that is passed in.
func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.FileserverHits = cfg.FileserverHits + 1
		next.ServeHTTP(w, r)
	})
	return fn
}

func cleanChirp(chirp string) string {
	words := strings.Split(chirp, " ")
	cleanedString := ""
	for _, word := range words {
		badWordFlag := false
		for _, bw := range badWords {
			if strings.EqualFold(word, bw) {
				badWordFlag = true
				break
			}
		}
		if !badWordFlag {
			cleanedString = cleanedString + " " + word
		} else {
			cleanedString = cleanedString + " " + "****"
		}
	}
	return cleanedString
}

// apiChirpHandler: Support GET and POST methods on chirps after validating it.
// stores the chirp
func (cfg *apiConfig) apiChirpPostHanlder(w http.ResponseWriter, r *http.Request) {
	// Get auth token
	auth := r.Header.Get("Authorization")
	auth = strings.TrimPrefix(auth, "Bearer ")

	// authetnicate user
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(auth, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.Jwtsecret), nil
	})
	if err != nil {
		fmt.Printf("%v\n", err)
		w.WriteHeader(401)
		return
	}
	// Checking token validity
	if !token.Valid {
		fmt.Printf("Token invalid\n")
		w.WriteHeader(401)
		return
	}
	// Get user ID from subject field in the claims
	userIDS, err := claims.GetSubject()
	if err != nil {
		fmt.Printf("%v\n", err)
		w.WriteHeader(401)
		return
	}
	userID, err := strconv.Atoi(userIDS)
	if err != nil {
		fmt.Printf("%v\n", err)
		w.WriteHeader(401)
		return
	}
	authorid := userID

	// holds request body
	type reqBodies struct {
		Body string `json:"body"`
	}

	// extract the contents of the request body
	reqBody := reqBodies{}
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&reqBody)
	if err != nil {
		fmt.Printf("Error decoding request body: %s", err)
		w.WriteHeader(500)
		return
	}

	// validate the chirp
	// 1. length should not be greater than 140 characters
	// 2. clean bad words off the chirp
	type validatedChirp struct {
		Valid       bool   `json:"valid"`
		CleanedBody string `json:"cleaned_body"`
		Error       string `json:"error"`
	}

	validChirp := validatedChirp{}
	bodyLen := len(reqBody.Body)
	if bodyLen > 140 {
		validChirp.Valid = false
		validChirp.Error = "Chirp is too long"
		w.WriteHeader(400)
	} else {
		validChirp.CleanedBody = cleanChirp(reqBody.Body)
		validChirp.Valid = true
		validChirp.Error = ""
	}

	// write to the database
	dbChirp, err := cfg.DB.CreateChirp(validChirp.CleanedBody, authorid)
	if err != nil {
		fmt.Printf("Unable to create a chirp in the database\n")
		w.WriteHeader(500)
		return
	}

	// write database results to responseWriter
	dat, err := json.Marshal(dbChirp)
	if err != nil {
		fmt.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(201)
	w.Header().Set("Content-Type", "application/json")
	w.Write(dat)
}

// apiChirpGetHandler read the database for all the chirps and
// write them as a response
func (cfg *apiConfig) apiChirpGetHanlder(w http.ResponseWriter, r *http.Request) {
	chirps, err := cfg.DB.GetChirps()
	if err != nil {
		fmt.Printf("Unable to get chirps form database\n")
		w.WriteHeader(500)
		return
	}

	// Get the chirp IP
	chirpIdStr := r.PathValue("chirpid")
	chirpId, err := strconv.Atoi(chirpIdStr)
	if err != nil {
		fmt.Printf("Unable to convert string to int\n")
		w.WriteHeader(500)
		return
	}

	if chirpId >= len(chirps) {
		w.WriteHeader(404)
		return
	}

	// write chirps to responseWriter
	dat, err := json.Marshal(chirps[chirpId])
	if err != nil {
		fmt.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(200)
	w.Header().Set("Content-Type", "application/json")
	w.Write(dat)
}

// apiChirpGetAllHandler: Get all chirps that have been posted by all users
func (cfg *apiConfig) apiChirpGetAllHanlder(w http.ResponseWriter, r *http.Request) {
	// extract optionaly query author_id parameter fro request
	qryauthorid := r.URL.Query().Get("author_id")
	authorid := -1
	sortorder := r.URL.Query().Get("sort")
	var err error
	if qryauthorid == "" {
		authorid = -1
	} else {
		authorid, err = strconv.Atoi(qryauthorid)
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(500)
			return
		}
	}

	chirps, err := cfg.DB.GetChirps()
	if err != nil {
		fmt.Printf("%v\n", err)
		w.WriteHeader(500)
		return
	}

	fmt.Println(authorid)
	fmt.Println(sortorder)
	// reschirps := chirps
	// if authorid != -1 {
	// 	// filter chirps based on author id
	// 	reschirps = make([]database.Chirp, 0)
	// 	for _, chirp := range chirps {
	// 		if chirp.Authorid == authorid {
	// 			reschirps = append(reschirps, chirp)
	// 		}
	// 	}
	// }

	// write chirps to responseWriter
	if strings.EqualFold(sortorder, "desc") {
		slices.Reverse(chirps)
	}

	dat, err := json.Marshal(chirps)
	if err != nil {
		fmt.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(200)
	w.Header().Set("Content-Type", "application/json")
	w.Write(dat)
}

func (cfg *apiConfig) apiDeleteChirpPageHandler(w http.ResponseWriter, r *http.Request) {
	// Get auth token
	auth := r.Header.Get("Authorization")
	auth = strings.TrimPrefix(auth, "Bearer ")

	// authetnicate user
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(auth, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.Jwtsecret), nil
	})
	if err != nil {
		fmt.Printf("%v\n", err)
		w.WriteHeader(401)
		return
	}
	// Checking token validity
	if !token.Valid {
		fmt.Printf("Token invalid\n")
		w.WriteHeader(401)
		return
	}
	// Get user ID from subject field in the claims
	userIDS, err := claims.GetSubject()
	if err != nil {
		fmt.Printf("%v\n", err)
		w.WriteHeader(401)
		return
	}
	userID, err := strconv.Atoi(userIDS)
	if err != nil {
		fmt.Printf("%v\n", err)
		w.WriteHeader(401)
		return
	}

	// delete chirp if author id matches the chirp's author id
	// otherwise do not delete chirp
	chirps, err := cfg.DB.GetChirps()
	if err != nil {
		fmt.Printf("Unable to get chirps form database\n")
		w.WriteHeader(500)
		return
	}
	// Get the chirp ID
	chirpIdStr := r.PathValue("chirpid")
	chirpId, err := strconv.Atoi(chirpIdStr)
	if err != nil {
		fmt.Printf("Unable to convert string to int\n")
		w.WriteHeader(500)
		return
	}
	if chirpId >= len(chirps) {
		w.WriteHeader(404)
		return
	}

	// delete chirp if user is author of chirp
	chirpauthorid := chirps[chirpId].Authorid
	if userID != chirpauthorid {
		// user is not the author of the chirp and
		// cannot delete chirp
		w.WriteHeader(403)
		return
	}
	err = cfg.DB.DeleteChirp(chirpId)
	if err != nil {
		fmt.Printf("%v\n", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(204)
}

func (cfg *apiConfig) apiUserPostHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the contents of the request
	type reqBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	reqData := reqBody{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&reqData)
	if err != nil {
		fmt.Printf("Error decoding request email: %s\n", err)
		w.WriteHeader(500)
		return
	}

	// Create user using email and password
	email := reqData.Email
	dbUser, err := cfg.DB.CreateUser(email, reqData.Password)
	if err != nil {
		fmt.Printf("Unable to create user in database\n")
		w.WriteHeader(500)
		return
	}

	// write user to response writer
	// return only email and ID and not the password
	type retBody struct {
		Email       string `json:"email"`
		ID          int    `json:"id"`
		Ischirpyred bool   `json:"is_chirpy_red"`
	}
	retVal := retBody{}
	retVal.Email = dbUser.Email
	retVal.ID = dbUser.ID
	retVal.Ischirpyred = dbUser.Ischirpyred

	dat, err := json.Marshal(retVal)
	if err != nil {
		fmt.Printf("Error marshalling JSON: %s\n", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(201)
	w.Header().Set("Content-Type", "application/json")
	w.Write(dat)
}

// apiUserGetHandler: read contents of users database and write to response
func (cfg *apiConfig) apiUserGetHandler(w http.ResponseWriter, r *http.Request) {
	// read the database
	users, err := cfg.DB.GetUsers()
	if err != nil {
		fmt.Printf("Unable to get users from database\n")
		w.WriteHeader(500)
		return
	}
	// write entire database to responsewriter
	dat, err := json.Marshal(users)
	if err != nil {
		fmt.Printf("Error marshalling JSON: %s\n", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(200)
	w.Header().Set("Content-Type", "application/json")
	w.Write(dat)
}

func (cfg *apiConfig) apiLoginPostHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the contents of the request
	type reqBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Expinsec int    `json:"expires_in_seconds"`
	}
	reqData := reqBody{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&reqData)
	if err != nil {
		fmt.Printf("Error decoding request email: %s\n", err)
		w.WriteHeader(500)
		return
	}
	if reqData.Expinsec == 0 || reqData.Expinsec > 60*60 {
		reqData.Expinsec = 60 * 60
	}

	// check password for user
	user, err := cfg.DB.CheckPass(reqData.Email, reqData.Password)
	if err != nil {
		fmt.Printf("%v\n", err)
		w.WriteHeader(401)
		return
	}

	// create JWT for user
	// 1. Create a new token with registered claims
	// 2. sign the token created with secret key
	// 3. send the signed token string
	// 4. Generate, sign and send a refresh token which is a randong 256 bit value

	jwtclaims := jwt.RegisteredClaims{}
	jwtclaims.Issuer = "chirpy"
	jwtclaims.IssuedAt = jwt.NewNumericDate(time.Now())
	jwtclaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Second * time.Duration(reqData.Expinsec)))
	jwtclaims.Subject = fmt.Sprint(user.ID)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtclaims)

	jwtsecret := cfg.Jwtsecret
	signedString, err := token.SignedString([]byte(jwtsecret))
	if err != nil {
		fmt.Printf("%v\n", err)
		w.WriteHeader(500)
		return
	}

	// Generate refresh token
	// expires in 60 days
	// a random 32 bytes of data is used as secret which
	// will be stored by the client in a db
	rtclaims := jwt.RegisteredClaims{}
	rtclaims.Issuer = "chirpy"
	rtclaims.IssuedAt = jwt.NewNumericDate(time.Now())
	rtclaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour * time.Duration(60*24)))
	rtclaims.Subject = fmt.Sprint(user.ID)
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, rtclaims)
	rtsecbts := make([]byte, 32)
	_, err = rand.Read(rtsecbts)
	if err != nil {
		fmt.Printf("%v\n", err)
		w.WriteHeader(500)
		return
	}
	rtsecret := hex.EncodeToString(rtsecbts)
	rtsignedstr, err := refreshToken.SignedString([]byte(rtsecret))
	if err != nil {
		fmt.Printf("%v\n", err)
		w.WriteHeader(500)
		return
	}

	// update refresh token in database
	_, err = cfg.DB.UpdateUserRfrshTkn(user.ID, rtsignedstr)
	if err != nil {
		fmt.Printf("%v\n", err)
		w.WriteHeader(500)
		return
	}

	// return only email and ID and not the password
	type retBody struct {
		Email       string `json:"email"`
		ID          int    `json:"id"`
		Token       string `json:"token"`
		Rfrshtkn    string `json:"refresh_token"`
		Ischirpyred bool   `json:"is_chirpy_red"`
	}
	retVal := retBody{}
	retVal.Email = user.Email
	retVal.ID = user.ID
	retVal.Token = signedString
	retVal.Rfrshtkn = rtsignedstr
	retVal.Ischirpyred = user.Ischirpyred

	dat, err := json.Marshal(retVal)
	if err != nil {
		fmt.Printf("Error marshalling JSON: %s\n", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(200)
	w.Header().Set("Content-Type", "application/json")
	w.Write(dat)
}

// apiUserPutHandler: update user email
func (cfg *apiConfig) apiUserPutHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the token from the request headers and strip off the Bearer prefix.
	auth := r.Header.Get("Authorization")
	auth = strings.TrimPrefix(auth, "Bearer ")

	// Use the jwt.ParseWithClaims function to validate the signature of the
	// JWT and extract the claims into a *jwt.Token struct.
	// An error will be returned if the token is invalid or has expired.
	// If the token is invalid, return a 401 Unauthorized response.
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(auth, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.Jwtsecret), nil
	})
	if err != nil {
		fmt.Printf("%v\n", err)
		w.WriteHeader(401)
		return
	}

	// Checking token validity
	if !token.Valid {
		fmt.Printf("Token invalid\n")
		w.WriteHeader(401)
		return
	}

	// Get user ID from subject field in the claims
	userIDS, err := claims.GetSubject()
	if err != nil {
		fmt.Printf("%v\n", err)
		w.WriteHeader(401)
		return
	}
	userID, err := strconv.Atoi(userIDS)
	if err != nil {
		fmt.Printf("%v\n", err)
		w.WriteHeader(401)
		return
	}

	// user is authenticated and user ID is obtained
	// parse request body for updated email and password
	// read the database and update the user email
	type reqBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	reqData := reqBody{}
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&reqData)
	if err != nil {
		fmt.Printf("Error decoding request: %s\n", err)
		w.WriteHeader(500)
		return
	}

	user, err := cfg.DB.UpdateUserEmailPass(userID, reqData.Email, reqData.Password)
	if err != nil {
		fmt.Printf("Error updating email and password: %s\n", err)
		w.WriteHeader(500)
		return
	}

	// return only email and ID and not the password
	type retBody struct {
		Email string `json:"email"`
		ID    int    `json:"id"`
	}
	retVal := retBody{}
	retVal.Email = user.Email
	retVal.ID = user.ID

	dat, err := json.Marshal(retVal)
	if err != nil {
		fmt.Printf("Error marshalling JSON: %s\n", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(200)
	w.Header().Set("Content-Type", "application/json")
	w.Write(dat)
}

func (cfg *apiConfig) apiRefreshPostHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	auth = strings.TrimPrefix(auth, "Bearer ")

	// check if authentiacation is present in database
	user, err := cfg.DB.CheckRfrshTkn(auth)
	if err != nil {
		fmt.Printf("%v", err)
		w.WriteHeader(401)
		return
	}

	// accepted create a new jwt token that expires in an hour
	jwtclaims := jwt.RegisteredClaims{}
	jwtclaims.Issuer = "chirpy"
	jwtclaims.IssuedAt = jwt.NewNumericDate(time.Now())
	jwtclaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour * time.Duration(1)))
	jwtclaims.Subject = fmt.Sprint(user.ID)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtclaims)
	jwtsecret := cfg.Jwtsecret
	signedString, err := token.SignedString([]byte(jwtsecret))
	if err != nil {
		fmt.Printf("%v\n", err)
		w.WriteHeader(500)
		return
	}

	// send response
	type retBody struct {
		Token string `json:"token"`
	}
	retVal := retBody{}
	retVal.Token = signedString
	dat, err := json.Marshal(retVal)
	if err != nil {
		fmt.Printf("Error marshalling JSON: %s\n", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(200)
	w.Header().Set("Content-Type", "application/json")
	w.Write(dat)
}

// apiRevokePostHandler: Revoke refresh token
func (cfg *apiConfig) apiRevokePostHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	auth = strings.TrimPrefix(auth, "Bearer ")

	err := cfg.DB.RevokeRfrshTkn(auth)
	if err != nil {
		fmt.Printf("%v\n", err)
		w.WriteHeader(500)
		return
	}

	// Request was successful, no body returned
	w.WriteHeader(204)
}

// apiPostPolkaHandler"
func (cfg *apiConfig) apiPostPolkaHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	auth = strings.TrimPrefix(auth, "ApiKey ")
	// check if webhook authorization matches API key
	if !(strings.EqualFold(auth, cfg.Polkakey)) {
		fmt.Printf("Auth: %s does not match polkakey: %s\n", auth, cfg.Polkakey)
		w.WriteHeader(401)
		return
	}

	// get the data from reqeust
	type whreqt struct {
		Event string `json:"event"`
		Data  struct {
			UserID int `json:"user_id"`
		} `json:"data"`
	}
	whreqdata := whreqt{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&whreqdata)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(500)
		return
	}

	if strings.EqualFold(whreqdata.Event, "user.upgraded") {
		// find user, if found, update his red status and return 204.
		// if user not found, return 404
		_, err := cfg.DB.UpdateUserChirpyRed(whreqdata.Data.UserID)
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(404)
			return
		}
		// request success, no body returned
		w.WriteHeader(204)
	} else {
		// dont care about event, return success
		w.WriteHeader(204)
		return
	}
}

func main() {
	const rootDir string = "./app"
	const healthPage string = "/api/healthz"
	const metricsPage string = "/admin/metrics"
	const resetPage string = "/api/reset"
	//const validateChirpPage string = "/api/validate_chirp"
	const apiChirpsPage string = "/api/chirps"
	const apiChirpsGetPage string = apiChirpsPage + "/{chirpid}"
	const apiUsersPostPage string = "POST /api/users"
	const apiUserGetPage string = "GET /api/users"
	const apiUserPutPage string = "PUT /api/users"
	const apiLoginPostPage string = "POST /api/login"
	const apiRefreshPostPage string = "POST /api/refresh"
	const apiRevokePostPage string = "POST /api/revoke"
	const apiDeleteChirpPage string = "DELETE " + apiChirpsPage + "/{chirpid}"
	const apiPostPolkaPage string = "POST /api/polka/webhooks"

	const appPort string = ":8080"
	const metricsTmpl string = "metrics.tmpl"
	cfg := apiConfig{}
	cfg.metricsTmpl = metricsTmpl

	// read environment variables from default .env file and store in configuration
	godotenv.Load()
	jwtsecret := os.Getenv("JWT_SECRET")
	cfg.Jwtsecret = jwtsecret
	cfg.Polkakey = os.Getenv("POLKA_KEY")

	// create a new database and add it to config
	myDB, e := database.NewDB("./database.json")
	if e != nil {
		fmt.Println(e)
		return
	}
	cfg.DB = myDB

	serveMux := http.NewServeMux()
	serveMux.HandleFunc("GET "+healthPage, healthEndPointHandler)       // health page handlw ith HandleFunc instead of file server
	serveMux.HandleFunc("GET "+metricsPage, cfg.metricsEndPointHandler) //metrics page handler register
	serveMux.HandleFunc(resetPage, cfg.resetMetricHandler)              // reset the metrics
	serveMux.HandleFunc("POST "+apiChirpsPage, cfg.apiChirpPostHanlder)
	serveMux.HandleFunc("GET "+apiChirpsGetPage, cfg.apiChirpGetHanlder)
	serveMux.HandleFunc("GET "+apiChirpsPage, cfg.apiChirpGetAllHanlder)
	serveMux.HandleFunc(apiUsersPostPage, cfg.apiUserPostHandler)
	serveMux.HandleFunc(apiUserGetPage, cfg.apiUserGetHandler)
	serveMux.HandleFunc(apiLoginPostPage, cfg.apiLoginPostHandler)
	serveMux.HandleFunc(apiUserPutPage, cfg.apiUserPutHandler)
	serveMux.HandleFunc(apiRefreshPostPage, cfg.apiRefreshPostHandler)
	serveMux.HandleFunc(apiRevokePostPage, cfg.apiRevokePostHandler)
	serveMux.HandleFunc(apiDeleteChirpPage, cfg.apiDeleteChirpPageHandler)
	serveMux.HandleFunc(apiPostPolkaPage, cfg.apiPostPolkaHandler)

	appHandler := http.StripPrefix("/app", http.FileServer(http.Dir(rootDir))) // file server handler
	appHandler = cfg.middlewareMetricsInc(appHandler)                          // with middleware attached
	serveMux.Handle("/app/*", appHandler)                                      // anything within the app folder, serve using file server

	// configure the server
	server := http.Server{}
	server.Addr = appPort
	server.Handler = serveMux

	fmt.Println("Root: localhost" + appPort + "/app/")
	fmt.Println("Health: localhost" + appPort + healthPage)
	fmt.Println("Metris: localhost" + appPort + metricsPage)
	fmt.Println("Reset metrics: localhost" + appPort + resetPage)

	err := server.ListenAndServe()
	if err != nil {
		fmt.Println(err)
	}
}
