package main

import (
	"bytes"
	"html/template"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var tpl = template.Must(template.ParseGlob("templates/*.html"))

// a very simple in-memory store
type Post struct {
    Author  string
    Content string
    Posted  time.Time
}

var (
    postsMu sync.Mutex
    posts   = []Post{}
)

func main() {
    // static assets
    fs := http.FileServer(http.Dir("static"))
    http.Handle("/static/", http.StripPrefix("/static/", fs))

    http.HandleFunc("/", index)
    http.HandleFunc("/verify", verify)
    http.HandleFunc("/forum", forum)
    http.HandleFunc("/post", createPost)

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
    // save cookie for Origo
    if err := exec.Command("bash", "-c",
        "echo "+shellQuote(cookie)+">../forum-app/cookie.txt",
    ).Run(); err != nil {
        http.Error(w, "failed to save cookie", 500)
        return
    }

    // run the Origo flow
    cmd := exec.Command("bash", "run.sh")
    cmd.Dir = "../forum-app"

    var out bytes.Buffer
    cmd.Stdout = &out
    cmd.Stderr = &out

    if err := cmd.Run(); err != nil {
        // on failure, show the log so you can debug
        http.Error(w, "verification failed:\n\n"+out.String(), 500)
        return
    }

    // success
    http.Redirect(w, r, "/forum", http.StatusSeeOther)
}

func forum(w http.ResponseWriter, r *http.Request) {
    postsMu.Lock()
    defer postsMu.Unlock()
    tpl.ExecuteTemplate(w, "forum.html", posts)
}

// handle new post submissions
func createPost(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Redirect(w, r, "/forum", http.StatusSeeOther)
        return
    }
    author := strings.TrimSpace(r.FormValue("author"))
    content := strings.TrimSpace(r.FormValue("content"))
    if content == "" {
        http.Redirect(w, r, "/forum", http.StatusSeeOther)
        return
    }
    postsMu.Lock()
    posts = append([]Post{{Author: author, Content: content, Posted: time.Now()}}, posts...)
    postsMu.Unlock()
    http.Redirect(w, r, "/forum", http.StatusSeeOther)
}

// naive shell-quoting
func shellQuote(s string) string {
    return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}