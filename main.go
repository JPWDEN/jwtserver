package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/authserver/service"
)

func main() {
	fmt.Printf("Starting service...\n")

	http.HandleFunc("/adduser", service.AddUser)
	http.HandleFunc("/addsvc", service.AddService)
	http.HandleFunc("/issue", service.IssueUserJWT)
	http.HandleFunc("/issuesvc", service.IssueServiceJWT)
	http.HandleFunc("/validate", service.ValidateUser)
	http.HandleFunc("/validatesvc", service.ValidateService)
	http.HandleFunc("/refresh", service.RefreshUserToken)
	http.HandleFunc("/refreshsvc", service.RefreshServiceToken)
	http.HandleFunc("/print", service.PrintUsers)

	log.Fatal(http.ListenAndServe(":8000", nil))
}
