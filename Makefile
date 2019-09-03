all: build

build:
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -v -o bin/secshift cmd/main.go
