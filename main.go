package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/go-httpproxy/httpproxy"
	"google.golang.org/api/iamcredentials/v1"
)

var serviceAccountPtr *string = nil

type tokenResponse struct {
	AccessToken string `json:"access_token,omitempty"`
	ExpiresIn   string `json:"expires_in,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
}

func onError(ctx *httpproxy.Context, where string, err *httpproxy.Error, opErr error) {
	// Log errors.
	log.Printf("ERR: %s: %s [%s]", where, err, opErr)
}

func onAccept(ctx *httpproxy.Context, w http.ResponseWriter, r *http.Request) bool {
	// Force requests to be proxied
	if !r.URL.IsAbs() {
		r.URL.Scheme = "http"
		r.URL.Host = "169.254.169.254"
	}

	if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/computeMetadata/v1/instance/service-accounts/default") {
		if strings.ToLower(r.Header.Get("Metadata-Flavor")) == "google" {
			parts := strings.Split(strings.TrimRight(r.URL.Path, "/"), "/")

			switch action := parts[len(parts)-1]; action {
			case "token":
				ctx := context.Background()
				iamcredentialsService, err := iamcredentials.NewService(ctx)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(fmt.Sprintf("Failed to initialize iamcredentials service: %s\n", err.Error())))
					return true
				}

				accessTokenRequest := iamcredentials.GenerateAccessTokenRequest{
					Lifetime: "3600s",
					Scope:    []string{"https://www.googleapis.com/auth/cloud-platform"}}

				iamcredentialsProjectsService := iamcredentialsService.Projects
				iamcredentialsServiceAccounts := iamcredentialsProjectsService.ServiceAccounts

				serviceAccount := fmt.Sprintf("projects/-/serviceAccounts/%s", *serviceAccountPtr)
				generateAccessTokenCall := iamcredentialsServiceAccounts.GenerateAccessToken(serviceAccount, &accessTokenRequest)
				token, err := generateAccessTokenCall.Do()
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(fmt.Sprintf("Failed to generate token: %s\n", err.Error())))
					return true
				}

				response := tokenResponse{AccessToken: token.AccessToken, ExpiresIn: token.ExpireTime, TokenType: "Bearer"}
				responseBytes, err := json.Marshal(response)
				w.Write(responseBytes)
			case "email":
				w.Write([]byte(*serviceAccountPtr))
			default:
				return false
			}
		} else {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Missing Metadata-Flavor:Google header.\n"))
			return true
		}

		return true
	}
	return false
}

func onConnect(ctx *httpproxy.Context, host string) (ConnectAction httpproxy.ConnectAction, newHost string) {
	// Don't support CONNECT, we don't need SSL
	return httpproxy.ConnectNone, host
}

func onRequest(ctx *httpproxy.Context, req *http.Request) (resp *http.Response) {
	// Overwrite to metadata endpoint IP address
	req.URL.Host = "169.254.169.254"

	// Log proxying requests.
	log.Printf("INFO: Proxy: %s %s", req.Method, req.URL.String())
	return
}

func onResponse(ctx *httpproxy.Context, req *http.Request, resp *http.Response) {
	resp.Header.Add("Via", "gce-impersonation-proxy")
}

func main() {
	serviceAccountPtr = flag.String("I", "", "Service Account to impersonate")
	bindAddress := flag.String("B", "127.0.0.1:80", "Bind address")
	flag.Parse()
	if *serviceAccountPtr == "" || *bindAddress == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	prx, _ := httpproxy.NewProxy()

	prx.OnError = onError
	prx.OnAccept = onAccept
	prx.OnAuth = nil
	prx.OnConnect = onConnect
	prx.OnRequest = onRequest
	prx.OnResponse = onResponse

	log.Fatal(http.ListenAndServe(*bindAddress, prx))
}
