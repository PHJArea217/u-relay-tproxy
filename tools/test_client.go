/*
 * go build -compiler gccgo test_client.go
 */
package main
import (
	"io"
	"os"
	"net/http"
)
func main() {
	http_stream, _ := http.Get("https://www.peterjin.org/time")
	d, _ := io.ReadAll(http_stream.Body)
	http_stream.Body.Close()
	os.Stdout.Write(d)
}
