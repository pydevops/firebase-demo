// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/storage"

	jwt "github.com/dgrijalva/jwt-go"
	gcontext "github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/mitchellh/mapstructure"

	"golang.org/x/net/context"
	"google.golang.org/api/option"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
)

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type GCSPath struct {
	Path string `json:"path"`
}
type JwtToken struct {
	Token string `json:"token"`
}
type Exception struct {
	Message string `json:"message"`
}

const (
	verifyPasswordURL = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key=%s"
	apiKey            = "AIzaSyDZwA-8oKtLWz6GyDVNNKr_v4nLaq57-Yo"
	bucket            = "pso-victory-dev.appspot.com"
	workDir           = "work_area"
)

var (
	ctx        context.Context
	authClient *auth.Client
	bh         *storage.BucketHandle
)

func signInWithPassword(email, password string) (string, error) {
	req, err := json.Marshal(map[string]interface{}{
		"email":    email,
		"password": password,
	})
	if err != nil {
		return "", err
	}

	resp, err := postRequest(fmt.Sprintf(verifyPasswordURL, apiKey), req)
	if err != nil {
		return "", err
	}
	var respBody struct {
		IDToken string `json:"idToken"`
	}
	if err := json.Unmarshal(resp, &respBody); err != nil {
		return "", err
	}
	//log.Printf("%v\n", respBody)
	return respBody.IDToken, err
}

func postRequest(url string, req []byte) ([]byte, error) {
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(req))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected http status code: %d", resp.StatusCode)
	}
	return ioutil.ReadAll(resp.Body)
}

func firebaseCloudStorage() *storage.BucketHandle {
	ctx := context.Background()
	config := &firebase.Config{
		StorageBucket: bucket,
	}
	opt := option.WithCredentialsFile("sa/firebase-adminsdk.json")
	app, err := firebase.NewApp(ctx, config, opt)
	if err != nil {
		log.Fatalln(err)
	}

	client, err := app.Storage(ctx)
	if err != nil {
		log.Fatalln(err)
	}

	bucket, err := client.DefaultBucket()
	if err != nil {
		log.Fatalln(err)
	}

	//log.Printf("Created bucket handle: %v\n", bucket)
	return bucket
}

func firebaseAuth() *auth.Client {
	ctx := context.Background()
	//Get a firebase.App
	opt := option.WithCredentialsFile("sa/firebase-adminsdk.json")
	app, err := firebase.NewApp(ctx, nil, opt)
	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
	}

	//Get an auth client from the firebase.App
	client, err := app.Auth(ctx)
	if err != nil {
		log.Fatalf("error getting Auth client: %v\n", err)
	}
	return client
}
func getUserByEmail(ctx context.Context, client *auth.Client, email string) *auth.UserRecord {
	// [START get_user_by_email_golang]
	u, err := client.GetUserByEmail(ctx, email)
	if err != nil {
		log.Fatalf("error getting user by email %s: %v\n", email, err)
	}
	log.Printf("Successfully fetched user data: %s\n", u.UID)
	// [END get_user_by_email_golang]
	return u
}
func CreateTokenEndpoint(w http.ResponseWriter, req *http.Request) {
	var user User
	_ = json.NewDecoder(req.Body).Decode(&user)

	_, err := signInWithPassword(user.Email, user.Password)
	if err != nil {
		json.NewEncoder(w).Encode(Exception{Message: "Invalid email/password"})
		log.Println(err)
		return
	}
	//log.Printf("firebaseIdToken=%s\n", firebaseIdToken)
	expireToken := time.Now().Add(time.Second * 20).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"exp":   expireToken,
	})
	tokenString, error := token.SignedString([]byte("WhatIssecret"))
	if error != nil {
		fmt.Println(error)
	}
	json.NewEncoder(w).Encode(JwtToken{Token: tokenString})
}

func ValidateJWToken(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authorizationHeader := req.Header.Get("Authorization")
		if authorizationHeader != "" {
			bearerToken := strings.Split(authorizationHeader, " ")
			if len(bearerToken) == 2 {
				token, error := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("There was an error")
					}
					return []byte("WhatIssecret"), nil
				})
				if error != nil {
					json.NewEncoder(w).Encode(Exception{Message: error.Error()})
					return
				}
				if token.Valid {
					gcontext.Set(req, "decoded", token.Claims)
					next(w, req)
				} else {
					json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"})
				}
			}
		} else {
			json.NewEncoder(w).Encode(Exception{Message: "An authorization header is required"})
		}
	})
}

func UploadEndpoint(w http.ResponseWriter, req *http.Request) {

	// get the user from the JWT token
	decoded := gcontext.Get(req, "decoded")
	var user User
	mapstructure.Decode(decoded.(jwt.MapClaims), &user)
	//log.Printf("user=%v", user)
	// parse and validate file and post parameters

	// Now we need to figure out
	// get firebase user id from firebase AuthClient
	fbUser := getUserByEmail(ctx, authClient, user.Email)
	log.Printf("userID:%s\n", fbUser.UID)

	// save the uploaded file to a work area on the server side
	file1, handler, err := req.FormFile("file1")
	if err != nil {
		renderError(w, "INVALID_FILE", http.StatusBadRequest)
		return
	}
	defer file1.Close()
	log.Printf("handler=%v", handler.Header)
	localFileName := workDir + "/" + handler.Filename
	localF, err := os.OpenFile(localFileName, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer localF.Close()
	io.Copy(localF, file1)

	//copy the file from work area to the bucket/$fbUserID/
	r, err := os.Open(localFileName)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer r.Close()
	objName := fbUser.UID + "/" + handler.Filename
	log.Println(objName)
	obj := bh.Object(objName)
	objWriter := obj.NewWriter(ctx)
	if _, err := io.Copy(objWriter, r); err != nil {
		log.Fatalln(err)
	}
	defer objWriter.Close()

	json.NewEncoder(w).Encode(GCSPath{Path: objName})
}
func renderError(w http.ResponseWriter, message string, statusCode int) {
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(message))
}

func main() {

	// init firebase admin SDK with auth & storage
	// validate as much as we can
	ctx = context.Background()
	authClient = firebaseAuth()
	bh = firebaseCloudStorage()
	if _, err := bh.Attrs(ctx); err != nil {
		log.Fatalln(err)
	}

	// set up RESTful side for login
	router := mux.NewRouter()
	router.HandleFunc("/login", CreateTokenEndpoint).Methods("POST")
	router.HandleFunc("/upload", ValidateJWToken(UploadEndpoint)).Methods("POST")
	log.Fatal(http.ListenAndServe(":9999", router))

}
