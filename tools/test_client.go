/*
 * go build -compiler gccgo test_client.go
 */
import (
	"io"
	"os"
	"net/http"
)
package main;

func main() {
	http_stream, _ := http.Get("https://www.peterjin.org/time")
	d, _ := io.ReadAll(http_stream.Body)
	http_stream.Body.Close()
	os.Stdout.Write(d)
}
