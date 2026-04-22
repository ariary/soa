BINARY = soa
SRC    = ./cmd/soa

.PHONY: build clean test

build:
	go build -o $(BINARY) $(SRC)

clean:
	rm -f $(BINARY)

test:
	go test ./...
