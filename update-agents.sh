#!/bin/bash
# generates payloads for each os

function build() {
GOOS=windows go build -o ../payloads/sandcat.go-windows -ldflags="-s -w" sandcat.go
GOOS=linux go build -o ../payloads/sandcat.go-linux -ldflags="-s -w" sandcat.go
GOOS=darwin go build -o ../payloads/sandcat.go-darwin -ldflags="-s -w" sandcat.go
GOOS=linux GOARCH=mips go build -o ../payloads/sandcat.go-linux-mips32 -ldflags="-s -w" gocat/sandcat.go
GOOS=linux GOARCH=arm GOARM=5 go build -o ../payloads/sandcat.go-linux-arm -ldflags="-s -w" gocat/sandcat.go
}
cd gocat && build
cd ..
