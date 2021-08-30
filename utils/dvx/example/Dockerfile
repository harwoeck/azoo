FROM ubuntu:latest

WORKDIR /tmp

RUN apt-get update && \
    apt-get install -y softhsm2 wget gcc tree && \
    wget -nv https://golang.org/dl/go1.16.6.linux-amd64.tar.gz && \
    rm -rf /usr/local/go &&  \
    tar -C /usr/local -xzf go1.16.6.linux-amd64.tar.gz && \
    rm -f go1.16.6.linux-amd64.tar.gz && \
    export PATH=$PATH:/usr/local/go/bin && \
    go version

ENV GOPATH /tmp/go
ENV PATH $PATH:/usr/local/go/bin:$GOPATH/bin
ENV CGO_ENABLED 1

COPY dvx/example/go.mod /app/dvx/example/go.mod
COPY dvx/example/go.sum /app/dvx/example/go.sum
COPY dvx/go.mod         /app/dvx/go.mod
COPY dvx/go.sum         /app/dvx/go.sum
COPY dvx/hsm/go.mod     /app/dvx/hsm/go.mod
COPY dvx/hsm/go.sum     /app/dvx/hsm/go.sum
COPY dvx/tearc/go.mod   /app/dvx/tearc/go.mod
COPY dvx/tearc/go.sum   /app/dvx/tearc/go.sum
COPY qr/go.mod          /app/qr/go.mod
COPY qr/go.sum          /app/qr/go.sum
COPY tearc/go.mod       /app/tearc/go.mod
COPY tearc/go.sum       /app/tearc/go.sum

WORKDIR /app/dvx/example

RUN go mod download
