FROM golang:1.18

ENV GO111MODULE=on

ADD . /usr/local/go/src/prisminspector
WORKDIR /usr/local/go/src/prisminspector
RUN go mod download && go mod verify 
RUN go build -v

CMD ["app"]