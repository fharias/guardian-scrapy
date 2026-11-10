package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/lento" {
			time.Sleep(10 * time.Second)
		}
		fmt.Fprintf(w, "hola desde el upstream\n")
		fmt.Fprintf(w, "ruta: %s\n", r.URL.Path)
		fmt.Fprintf(w, "Host: %s\n", r.Host)
		fmt.Fprintf(w, "X-Forwarded-For: %s\n", r.Header.Get("X-Forwarded-For"))
		fmt.Fprintf(w, "X-Forwarded-Host: %s\n", r.Header.Get("X-Forwarded-Host"))
		fmt.Fprintf(w, "X-Forwarded-Proto: %s\n", r.Header.Get("X-Forwarded-Proto"))
	})
	log.Println("upstream escuchando en :9000")
	log.Fatal(http.ListenAndServe(":9000", nil))
}
