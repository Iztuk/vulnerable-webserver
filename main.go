package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

var tmpl = template.Must(template.New("index").Parse(`
<!DOCTYPE html>
<html>
<head><title>Vuln Server</title></head>
<body>
{{.Content}}
</body>
</html>
`))


func main() {
	db, _ := sql.Open("sqlite3", "./vuln.db")
	defer db.Close()

	db.Exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)")
	// Seed data
	db.Exec("INSERT INTO users (name) VALUES ('admin')")
	db.Exec("INSERT INTO users (name) VALUES ('john')")
	db.Exec("INSERT INTO users (name) VALUES ('alice')")
	db.Exec("INSERT INTO users (name) VALUES ('bob')")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl.Execute(w, map[string]interface{}{
			"Content": template.HTML(`<h2>Welcome</h2>
		
		<form method="GET" action="/search">
		  Search user: <input name="name">
		  <input type="submit">
		</form>
		
		<br>
		
		<form method="POST" action="/comment">
		  Leave a comment: <textarea type="textarea" name="comment"></textarea>
		  <input type="submit">
		</form>
		
		<br>
		
		<form method="POST" enctype="multipart/form-data" action="/upload">
		  Upload a file: <input type="file" name="file">
		  <input type="submit">
		</form>
		`)})		
	})

	http.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name) // ❌ SQL injection
		rows, err := db.Query(query)
		if err != nil {
			http.Error(w, "Query error", 500)
			return
		}
		defer rows.Close()

		var output string
		for rows.Next() {
			var id int
			var name string
			rows.Scan(&id, &name)
			output += fmt.Sprintf("ID: %d, Name: %s\n", id, name)
		}
		fmt.Fprint(w, "<pre>"+output+"</pre>")
	})

	http.HandleFunc("/comment", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.ParseForm()
			comment := r.Form.Get("comment") // ❌ vulnerable to XSS
	
			content := fmt.Sprintf(`<h2>Thank you for your comment!</h2>
			<p>You said: %s</p>
			<a href="/">Back</a>`, comment)
	
			tmpl.Execute(w, map[string]interface{}{
				"Content": template.HTML(content), // injecting raw HTML
			})
		}
	})
	

	http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			file, handler, err := r.FormFile("file")
			if err != nil {
				http.Error(w, "Error reading file", 500)
				return
			}
			defer file.Close()
	
			// Make sure ./uploads/ folder exists
			err = os.MkdirAll("./uploads", os.ModePerm)
			if err != nil {
				http.Error(w, "Failed to create upload directory", 500)
				return
			}
	
			path := "./uploads/" + handler.Filename
			dst, err := os.Create(path)
			if err != nil {
				http.Error(w, "Failed to save file", 500)
				return
			}
			defer dst.Close()
			io.Copy(dst, file)
	
			// Make file executable (Linux/Mac only)
			exec.Command("chmod", "+x", path).Run()
	
			// Demo only: automatically execute uploaded shell script
			if strings.HasSuffix(handler.Filename, ".sh") {
				cmd := exec.Command("bash", path)
				err := cmd.Start()
				if err != nil {
					fmt.Printf("Error executing script: %v\n", err)
				}
			}

			if strings.HasSuffix(handler.Filename, ".bat") {
				cmd := exec.Command("cmd", "/C", "start", "", path)
				err := cmd.Start()
				if err != nil {
					fmt.Printf("Error executing script: %v\n", err)
				}
			}
	
			fmt.Fprintf(w, "File uploaded to ./uploads/%s and executed (if applicable).", handler.Filename)
		}
	})
	

	fmt.Println("Server running on http://localhost:8080")
	http.ListenAndServe("0.0.0.0:8080", nil)
}
