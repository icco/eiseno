all: local

local:
	go run main.go

build:
	go build main.go

install:
	go install -v -tags heroku .

clean:
	go clean
