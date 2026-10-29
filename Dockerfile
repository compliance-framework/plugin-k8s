FROM golang:1.26-alpine AS builder
# Build with the go.mod toolchain line (Renovate bumps it for Go security fixes), downloading it when this image's Go is older.
ENV GOTOOLCHAIN=auto

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /plugin .

FROM alpine:3.21

RUN apk add --no-cache ca-certificates
COPY --from=builder /plugin /plugin
ENTRYPOINT ["/plugin"]
