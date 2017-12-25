package daemon

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"time"

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
		errc <- run(laddr, db, notify)
		donec <- nil
	}()

	return errc, donec
}

func run(laddr string, db *mgo.Database, notify <-chan os.Signal) error {
	if db == nil {
		return mineme.ErrDBIsNil
	}
	l, err := net.Listen("tcp", laddr)
	if err != nil {
		return err
	}
	router := makeRoutes()
	http.Serve(l, router)
	return nil
}

func makeRoutes() http.Handler {
	router := mux.NewRouter()
	hostname, _ := os.Hostname()
	router = router.Host(hostname).Subrouter()
	router.Handle("/", http.FileServer(http.Dir("./assets/")))
	router.Handle("/login", authreq{loginHandler})
	router.Handle("/logout", authreq{logoutHandler})
	return nil
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
	Result  string          `json:"result,omitempty"`
	User    *mineme.User    `json:"user,omitempty"`
	Session *mineme.Session `json:"session,omitempty"`
}

//ErrorResponse for errors
type ErrorResponse struct {
	Code   code   `json:"code,omitempty"`
	Text   string `json:"text,omitempty"`
	Status bool   `json:"status,omitempty"`
}

type code int

//StatusCodes for errors
const (
	LOGINNOTFOUND code = 1001 + iota
	LOGINREQUIRED
	NOTLOGGEDIN
)

//FillErrorResponse unifies responses
func FillErrorResponse(c code) *ServerResponse {
	switch c {
	case LOGINREQUIRED:
		return &ServerResponse{
			Result: "error",
			ErrResponse: &ErrorResponse{
				Code: c,
				Text: "You need to be logged in to proceed this action",
			},
		}
	case NOTLOGGEDIN:
		return &ServerResponse{
			Result: "error",
			ErrResponse: &ErrorResponse{
				Code: c,
				Text: "You are not logged in",
			},
		}
	default:
		return &ServerResponse{
			Result: "error",
			ErrResponse: &ErrorResponse{
				Code: c,
				Text: "Bad Request",
			},
		}
	}

}

type authreq struct {
	next http.HandlerFunc
}

func (a authreq) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session, _ := sManager.SessionStart(w, r)
	if session.UserID == uuid.Nil {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Add("Content-Type", "application/json; encoding=utf8")
		json.NewEncoder(w).Encode(FillErrorResponse(LOGINREQUIRED))
		return
	}
	session.Created = time.Now().Unix()
	a.next.ServeHTTP(w, r)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	session, ok := r.Context().Value(mineme.SessionContext("sessionid")).(string)
	if !ok {
		loginAuthHandler(w, r)
		return
	}
	sid, _ := uuid.Parse(session)
	s := &mineme.Session{
		SessionID: sid,
	}
	err := sManager.LoadSessionUUID(s)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Add("Content-Type", "application/json; encoding=utf8")
		json.NewEncoder(w).Encode(FillErrorResponse(LOGINNOTFOUND))
		return
	}
	if s.UserID == uuid.Nil {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Add("Content-Type", "application/json; encoding=utf8")
		json.NewEncoder(w).Encode(FillErrorResponse(LOGINNOTFOUND))
		return
	}

}

func loginAuthHandler(w http.ResponseWriter, r *http.Request) {
	u := &mineme.User{}
	err := json.NewDecoder(r.Body).Decode(u)
	if err != nil {
		seresp := FillErrorResponse(http.StatusBadRequest)
		seresp.ErrResponse.Text = "Bad Request"
		w.WriteHeader(http.StatusNotFound)
		w.Header().Add("Content-Type", "application/json; encoding=utf8")
		json.NewEncoder(w).Encode(&seresp)
		return
	}
	err = model.AuthUser(u)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Add("Content-Type", "application/json; encoding=utf8")
		json.NewEncoder(w).Encode(FillErrorResponse(LOGINNOTFOUND))
		return
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, ok := r.Context().Value(mineme.SessionContext("sessionid")).(string)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Add("Content-Type", "application/json; encoding=utf8")
		json.NewEncoder(w).Encode(FillErrorResponse(NOTLOGGEDIN))
		return
	}
	sid, _ := uuid.Parse(session)
	s := &mineme.Session{SessionID: sid}
	sManager.DeleteSession(s)
	http.Redirect(w, r, "/", http.StatusFound)
	return
}
