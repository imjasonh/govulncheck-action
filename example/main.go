package main

import (
	"strings"

	"golang.org/x/net/html"
)

func main() {
	// html.Parse in x/net/html has a vulnerability in the version we depend on. The action should find it.
	_, err := html.Parse(strings.NewReader(`<html><body><p>hello</p></body></html>`))
	if err != nil {
		panic(err)
	}
}
