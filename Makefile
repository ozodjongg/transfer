.PHONY: test vet build windows linux clean

test:
	go test ./...

vet:
	go vet ./...

build:
	mkdir -p bin
	go build -trimpath -ldflags="-s -w" -o bin/server ./cmd/server
	go build -trimpath -ldflags="-s -w" -o bin/transfer ./cmd/client
	cp config.json bin/config.json

linux:
	mkdir -p bin
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/server-linux-amd64 ./cmd/server
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/transfer-linux-amd64 ./cmd/client

windows:
	mkdir -p bin
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/server.exe ./cmd/server
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/transfer.exe ./cmd/client
	cp bin/transfer.exe bin/client.exe
	cp config.json bin/config.json

clean:
	rm -rf bin downloads
