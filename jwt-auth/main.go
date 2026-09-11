package main

import (
	"log"
	"net/http"
)

func Hi(rw http.ResponseWriter, r *http.Request) {
	_, err := rw.Write([]byte(`hi`))
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
}

func setupRouter() *http.ServeMux {

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", Hi)

	return mux
}

func main() {

	mux := setupRouter()

	log.Println("Server up and listening on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", mux))

}
