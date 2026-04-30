.PHONY: build clean test

build:
	go build -o soa ./cmd/soa
	go build -o tonga ./cmd/tonga

clean:
	rm -f soa tonga

test:
	go test ./...
