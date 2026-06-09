FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download || true

COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -o /envelope-api .

FROM alpine:3.20

WORKDIR /app
COPY --from=builder /envelope-api ./envelope-api

CMD ["./envelope-api"]
