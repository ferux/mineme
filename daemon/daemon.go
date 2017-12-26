package daemon

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/mgo.v2/bson"

	"github.com/google/uuid"

	"github.com/gorilla/mux"

	"github.com/ferux/mineme/mineme"

	"gopkg.in/mgo.v2"
)

var logger *log.Logger
var sManager *mineme.SessionManager
var model *mineme.Model

//Run http backend server
func Run(laddr string, db *mgo.Database, debug bool, debugW io.Writer, notify <-chan os.Signal) (chan error, chan interface{}) {
	donec := make(chan interface{}, 1)
	errc := make(chan error, 0)
	go func() {
		if debug {
			logger = log.New(debugW, "[Daemon] ", log.Ldate+log.Ltime)
		} else {
			logger = log.New(ioutil.Discard, "", 0)
		}
		logger.Println("DB available:", db.Session.Ping() == nil)
		errc <- run(laddr, db, notify, debug, debugW)
		donec <- nil
	}()

	return errc, donec
}

func run(laddr string, db *mgo.Database, notify <-chan os.Signal, debug bool, debugW io.Writer) error {
	if db == nil {
		return mineme.ErrDBIsNil
	}
	l, err := net.Listen("tcp", laddr)
	if err != nil {
		return err
	}
	sManager, _ = mineme.NewSessionManager(db, debug, debugW)
	model, _ = mineme.NewModel(db, debug, debugW)
	router := makeRoutes()
	motd := "* Begin listening for new requests *"
	logger.Println(strings.Repeat("*", len(motd)))
	logger.Println(motd)
	logger.Println(fmt.Sprintf("%s%s", strings.Repeat("*", len(motd)), strings.Repeat("\n", 2)))
	return http.Serve(l, router)
}

func makeRoutes() http.Handler {
	router := mux.NewRouter()
	hostname, _ := os.Hostname()
	router = router.Host(hostname).Subrouter()
	router.Handle("/", http.FileServer(http.Dir("./assets/")))
	router.HandleFunc("/login", loginHandler).Methods("POST")
	router.Handle("/logout", authreq{logoutHandler}).Methods("POST")
	return router
}

//ServerResponse back to client
type ServerResponse struct {
	Result      string          `json:"result,omitempty"`
	ErrResponse *ErrorResponse  `json:"err_response,omitempty"`
	Session     *mineme.Session `json:"session,omitempty"`
	User        *mineme.User    `json:"user,omitempty"`
}

//ClientRequest from client
type ClientRequest struct {
	Result string `json:"result,omitempty"`
	User   *struct {
		Login       string `json:"login,omitempty"`
		FirstName   string `json:"first_name,omitempty"`
		LastName    string `json:"last_name,omitempty"`
		Password    string `json:"password,omitempty"`
		Description string `json:"description,omitempty"`
		Age         int    `json:"age,omitempty"`
	} `json:"user,omitempty"`
}

//ErrorResponse for errors
type ErrorResponse struct {
	Code    code   `json:"code,omitempty"`
	Text    string `json:"text,omitempty"`
	Status  bool   `json:"status,omitempty"`
	ByteArr []byte `json:"byte_arr,omitempty"`
}

type code int

//StatusCodes for errors
const (
	LOGINNOTFOUND code = 1001 + iota
	LOGINREQUIRED
	NOTLOGGEDIN
	ALREADYLOGGEDIN
)

//FillErrorResponse unifies responses
func FillErrorResponse(c code) *ServerResponse {
	switch c {
	case LOGINREQUIRED:
		return &ServerResponse{
			Result: "error",
			ErrResponse: &ErrorResponse{
				Code:    c,
				Text:    "You need to be logged in to proceed this action",
				Status:  false,
				ByteArr: md5.New().Sum([]byte("whathappenedhere??????")),
			},
		}
	case NOTLOGGEDIN:
		return &ServerResponse{
			Result: "error",
			ErrResponse: &ErrorResponse{
				Code:    c,
				Text:    "You are not logged in",
				Status:  false,
				ByteArr: md5.New().Sum([]byte("whathappenedhere??????")),
			},
		}
	case http.StatusBadRequest:
		return &ServerResponse{
			Result: "error",
			ErrResponse: &ErrorResponse{
				Code:    c,
				Text:    "Something went wrong and ended with an error. Sorry.",
				Status:  false,
				ByteArr: md5.New().Sum([]byte("whathappenedhere??????")),
			},
		}
	case ALREADYLOGGEDIN:
		return &ServerResponse{
			Result: "error",
			ErrResponse: &ErrorResponse{
				Code:    c,
				Text:    "You are already logged in",
				Status:  false,
				ByteArr: md5.New().Sum([]byte("whathappenedhere??????")),
			},
		}
	default:
		return &ServerResponse{
			Result: "error",
			ErrResponse: &ErrorResponse{
				Code:    c,
				Text:    "Bad Request",
				Status:  false,
				ByteArr: md5.New().Sum([]byte("whathappenedhere??????")),
			},
		}
	}

}

type authreq struct {
	next http.HandlerFunc
}

func (a authreq) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session, _ := sManager.SessionStart(w, r)
	if session == nil {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Add("Content-Type", "application/json; encoding=utf8")
		json.NewEncoder(w).Encode(FillErrorResponse(http.StatusBadRequest))
		return
	}
	u, err := sManager.LoadUser(session)
	logger.Println("Is there any errors during search:", err)
	if session.UserID == uuid.Nil {
		logger.Printf("User auth required to perform this action: %s", r.RequestURI)
		w.WriteHeader(http.StatusNotFound)
		w.Header().Add("Content-Type", "application/json; encoding=utf8")
		json.NewEncoder(w).Encode(FillErrorResponse(LOGINREQUIRED))
		return
	}
	logger.Printf("User %s has been logged in", u)
	ctx := context.WithValue(r.Context(), mineme.SessionContext("sessionid"), session.SessionID.String())
	r = r.WithContext(ctx)
	logger.Println("Adding sessionid to context")
	session.Created = time.Now().Unix()
	a.next.ServeHTTP(w, r)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := sManager.SessionStart(w, r)
	if session == nil {
		logger.Println("Session is nil. That is STRANGE!")
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Add("Content-Type", "application/json; encoding=utf8")
		json.NewEncoder(w).Encode(FillErrorResponse(http.StatusBadRequest))
		return
	}
	// u, _ := sManager.LoadUser(session)
	// if u.ID != uuid.Nil {
	// 	logger.Printf("Found user: %v", u)
	// 	w.WriteHeader(http.StatusOK)
	// 	w.Header().Add("Content-Type", "application/json; encoding=utf8")
	// 	json.NewEncoder(w).Encode(FillErrorResponse(ALREADYLOGGEDIN))
	// 	return
	// }
	if session.UserID != uuid.Nil {
		logger.Printf("Found user by session.UserID: %v", session.UserID)
		u := &mineme.User{ID: session.UserID}
		if !model.CheckUserExists("", "", u) {
			logger.Println("but this user doesn't exist")
			w.WriteHeader(http.StatusNotFound)
			w.Header().Add("Content-Type", "application/json; encoding=utf8")
			json.NewEncoder(w).Encode(FillErrorResponse(LOGINNOTFOUND))
			return
		}
		logger.Println("and this user exists")
		w.WriteHeader(http.StatusOK)
		w.Header().Add("Content-Type", "application/json; encoding=utf8")
		json.NewEncoder(w).Encode(FillErrorResponse(ALREADYLOGGEDIN))
		return
	}
	logger.Printf("Current session do not have assosiated user. Trying to authenticate current user")
	if ctype := r.Header.Get("content-type"); ctype != "application/json" {
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Add("Content-Type", "application/json; encoding=utf8")
		json.NewEncoder(w).Encode(FillErrorResponse(http.StatusBadRequest))
		return
	}
	//TODO: Separate creation a new user and login new user to different pathes
	var cresponse *ClientRequest
	err := json.NewDecoder(r.Body).Decode(&cresponse)
	if err != nil || cresponse == nil || cresponse.User == nil {
		logger.Printf("Got an error trying to proceed user register: %v", err)
		w.WriteHeader(http.StatusNotFound)
		w.Header().Add("Content-Type", "application/json; encoding=utf8")
		json.NewEncoder(w).Encode(FillErrorResponse(http.StatusBadRequest))
		return
	}
	logger.Printf("Found ClientRespose: %+v", *cresponse)
	logger.Printf("Here we should handler user registration. Got credentials: %s:%s", cresponse.User.Login, cresponse.User.Password)
	logger.Printf("Trying to authenticate user...")
	if !model.CheckUserExists(cresponse.User.Login, cresponse.User.Password, nil) {
		userNew, err := model.CreateNewUser(cresponse.User.Login, cresponse.User.Password, cresponse.User.FirstName, cresponse.User.LastName, cresponse.User.Age)
		if err != nil || userNew == nil {
			logger.Printf("Got an error trying to proceed user register: %v", err)
			w.WriteHeader(http.StatusNotFound)
			w.Header().Add("Content-Type", "application/json; encoding=utf8")
			json.NewEncoder(w).Encode(FillErrorResponse(http.StatusBadRequest))
			return
		}
		logger.Printf("Created new user: %v", userNew)
		session.UserID = userNew.ID
	} else {
		logger.Println("Found user. Assigning session to this user")
		encryptedPassword := md5.Sum([]byte(cresponse.User.Password))
		u := &mineme.User{Login: cresponse.User.Login, Password: encryptedPassword}
		model.AuthUser(u)
		session.UserID = u.ID
	}
	if session.OID == "" {
		session.OID = bson.NewObjectId()
	}
	sManager.CreateSession(session)
	logger.Printf("Session %s has been stored to the database", session.OID)
	w.WriteHeader(http.StatusOK)
	w.Header().Add("Content-Type", "text/plain; encoding=utf8")
	w.Write([]byte("ok"))
}

func loginAuthHandler(w http.ResponseWriter, r *http.Request) {
	req := &ClientRequest{}
	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil || req.User == nil {
		seresp := FillErrorResponse(http.StatusBadRequest)
		seresp.ErrResponse.Text = "Bad Request"
		w.WriteHeader(http.StatusNotFound)
		w.Header().Add("Content-Type", "application/json; encoding=utf8")
		json.NewEncoder(w).Encode(&seresp)
		return
	}
	// err = model.AuthUser(req.User)
	// if err != nil {
	// 	w.WriteHeader(http.StatusNotFound)
	// 	w.Header().Add("Content-Type", "application/json; encoding=utf8")
	// 	json.NewEncoder(w).Encode(FillErrorResponse(LOGINNOTFOUND))
	// 	return
	// }
	// if req.User.ID == uuid.Nil {
	// 	req.User.ID = uuid.New()
	// 	req.User.Age = 0
	// 	req.User.Group = mineme.USER
	// 	req.User.Status = mineme.USERAPPROVED
	// 	req.User.FirstName = "Guess"
	// 	req.User.LastName = "who?"
	// 	model.Create(req.User)
	// }
	// session, _ := r.Context().Value(mineme.SessionContext("sessionid")).(string)
	// sid, _ := uuid.Parse(session)
	// s := &mineme.Session{
	// 	SessionID: sid,
	// }
	// sManager.LoadSessionUUID(s)
	// s.UserID = req.User.ID
	// s.Created = time.Now().Unix()
	// sManager.UpdateSession(s)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// SessionContext("sessionid")
	sessionInt := r.Context().Value(mineme.SessionContext("sessionid"))
	session, ok := sessionInt.(string)
	logger.Printf("Just debug info: %v %v", sessionInt, ok)
	if session == "" || !ok {
		logger.Println("Can't retrieve session from context")
		w.WriteHeader(http.StatusNotFound)
		w.Header().Add("Content-Type", "application/json; encoding=utf8")
		json.NewEncoder(w).Encode(FillErrorResponse(NOTLOGGEDIN))
		return
	}
	logger.Println("Converting sessionid to uuid type")
	sid, _ := uuid.Parse(session)
	s := &mineme.Session{SessionID: sid}
	logger.Println("Deleting session from database")
	err := sManager.DeleteSession(s)
	if err != nil {
		logger.Println("Can't delete session. Reason: ", err)
	}
	sManager.SessionEnd(w, r)
	http.Redirect(w, r, "/", http.StatusFound)
}
