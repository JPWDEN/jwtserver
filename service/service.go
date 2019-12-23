package service

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"

	"github.com/authserver/key"
)

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	jwtKey   []byte
}

//UserClaims defines claims specifically for a user token
type UserClaims struct {
	Username string   `json:"username"`
	Products []string `json:"products"`
	jwt.StandardClaims
}

//ServiceClaims defines claims specifically for a service token
type ServiceClaims struct {
	Service string `json:"service"`
	jwt.StandardClaims
}

const (
	acme = "acme"
)

var users = map[string]Credentials{
	"user1": Credentials{
		Password: "passwd1",
	},
}
var services = map[string]string{
	"service1": "svcpass1",
}

func returnKey(token *jwt.Token) (interface{}, error) {
	data := strings.Split(token.Raw, ".")
	claimData, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(data[1])
	if err != nil {
		return nil, err
	}
	claims := UserClaims{}
	err = json.Unmarshal(claimData, &claims)
	if err != nil {
		return nil, err
	}
	user, ok := users[claims.Username]
	if !ok {
		return nil, nil
	}
	return user.jwtKey, nil
}

func AddUser(writer http.ResponseWriter, req *http.Request) {
	var creds Credentials
	creds.Username = req.Header.Get("username")
	creds.Password = req.Header.Get("password")
	creds.jwtKey = key.GenerateKey()
	users[creds.Username] = creds
	return
}

func PrintUsers(writer http.ResponseWriter, req *http.Request) {
	var body string
	for key, value := range users {
		body += fmt.Sprintf("%s/%s\n", key, value)
	}
	resp := http.Response{
		Body: ioutil.NopCloser(bytes.NewBufferString(body)),
	}
	buff := bytes.NewBuffer(nil)
	resp.Write(buff)
}

func AddService(writer http.ResponseWriter, req *http.Request) {

}

func IssueUserJWT(writer http.ResponseWriter, req *http.Request) {
	fmt.Println("Issuing JWT for user")
	var creds Credentials
	creds.Username = req.Header.Get("username")
	creds.Password = req.Header.Get("password")
	if creds.Username == "" || creds.Password == "" {
		writer.WriteHeader((http.StatusBadRequest))
		return
	}
	userCred, ok := users[creds.Username]
	if !ok || userCred.Password != creds.Password {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}

	//Good to go, create token
	userCred.jwtKey = key.GenerateKey()
	//By the way, run GenerateKeyCrypto to see if it produces better entropy
	//key.GenerateKeyCrypto()
	users[creds.Username] = userCred
	expiration := time.Now().Add(time.Minute * 5) //5-minute expiration
	claims := &UserClaims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiration.Unix(),
		},
	}

	//TODO:  Generally, there would be some db call here that would allow a user to be looked up in a table and products
	//that user was authenticated to use would be returned, and added to claims.Products.  here we are simplifying:
	claims.Products = append(claims.Products, acme)
	fmt.Printf("CLAIMS: %+v\n", claims)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(userCred.jwtKey) //Sign with our secret key
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	fmt.Printf("USERS: %+v\n---------\n", users)
	bearer := fmt.Sprintf("Bearer: %s", tokenStr)
	writer.Header().Set("Authorization", bearer)
	return
}

func IssueServiceJWT(writer http.ResponseWriter, req *http.Request) {

}

func ValidateUser(writer http.ResponseWriter, req *http.Request) {
	fmt.Println("Validating JWT for user")
	tokenString := req.Header.Get("Authorization")
	if len(tokenString) == 0 {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	claims := &UserClaims{}
	token, err := jwt.ParseWithClaims(strings.TrimPrefix(tokenString, "Bearer: "), claims, returnKey)
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	if !token.Valid {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	fmt.Printf("USERS: %+v\n---------\n", users)

	//TODO:  Check that the product usage is correct

	writer.Header().Set("Valid", "true")
}

func ValidateService(writer http.ResponseWriter, req *http.Request) {

}

func RefreshUserToken(writer http.ResponseWriter, req *http.Request) {
	fmt.Println("Refreshing JWT for user")
	tokenString := req.Header.Get("Authorization")
	if len(tokenString) == 0 {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	claims := &UserClaims{}
	oldToken, err := jwt.ParseWithClaims(strings.TrimPrefix(tokenString, "Bearer: "), claims, returnKey)
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			fmt.Printf("Signature error in JWT: %v\n", err)
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Printf("Error parsing JWT: %v\n", err)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	if !oldToken.Valid {
		fmt.Printf("Old token not valid: %v\n", err)
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}

	//If JWT has more than 30 seconds left, dont refresh it.
	fmt.Printf("EXPIRES/NOW + 30: %+v/%+v\n", claims.ExpiresAt, time.Now().Unix()+30)
	if claims.ExpiresAt > time.Now().Unix()+30 {
		writer.WriteHeader(http.StatusTemporaryRedirect)
		return
	}

	user, ok := users[claims.Username]
	if !ok {

	}
	user.jwtKey = key.GenerateKey()
	users[claims.Username] = user

	expiration := time.Now().Add(time.Minute * 5) //5-minute expiration
	claims.ExpiresAt = expiration.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenSigned, err := token.SignedString(user.jwtKey)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	fmt.Printf("USERS: %+v\n---------\n", users)
	writer.Header().Set("Authorization", fmt.Sprintf("Bearer: %s", tokenSigned))
	return
}

func RefreshServiceToken(writer http.ResponseWriter, req *http.Request) {

}
