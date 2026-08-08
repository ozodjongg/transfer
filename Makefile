.PHONY: test vet build windows clean

test:
	go test ./...

vet:
	go vet ./...

build:
	mkdir -p bin
	go build -trimpath -ldflags="-s -w" -o bin/server ./cmd/server
	go build -trimpath -ldflags="-s -w" -o bin/client ./cmd/client
	cp config.json bin/config.json

windows:
	mkdir -p bin
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/server-windows-amd64.exe ./cmd/server
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/client-windows-amd64.exe ./cmd/client
	cp config.json bin/config.json

clean:
	rm -rf bin downloads
