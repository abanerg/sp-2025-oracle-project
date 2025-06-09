package main

import (
	"html/template"
	"log"
	"net/http"
	"os/exec"
	"strings"
)

var tpl = template.Must(template.ParseGlob("templates/*.html"))

func main() {
    http.HandleFunc("/", index)
    http.HandleFunc("/verify", verify)
    http.HandleFunc("/forum", forum)
    log.Println("listening on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func index(w http.ResponseWriter, r *http.Request) {
    tpl.ExecuteTemplate(w, "index.html", nil)
}

func verify(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Redirect(w, r, "/", http.StatusSeeOther)
        return
    }
    cookie := r.FormValue("cookie")
    // write cookie to the file your origo client expects:
    if err := exec.Command("bash", "-c", "echo "+shellQuote(cookie)+">client/local_storage/cookie.txt").Run(); err != nil {
        http.Error(w, "failed to save cookie", 500)
        return
    }
    // now invoke your existing run.sh up through step 5 (handshake + proof):
    cmd := exec.Command("bash", "../run.sh")
    cmd.Stdout = w // for simplicity, you could buffer & detect success/fail
    cmd.Stderr = w
    if err := cmd.Run(); err != nil {
        http.Error(w, "verification failed:\n"+err.Error(), 500)
        return
    }
    // success → redirect to forum
    http.Redirect(w, r, "/forum", http.StatusSeeOther)
}

func forum(w http.ResponseWriter, r *http.Request) {
    tpl.ExecuteTemplate(w, "forum.html", nil)
}

// shellQuote makes a really naive single-quote wrapper:
func shellQuote(s string) string {
    return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
