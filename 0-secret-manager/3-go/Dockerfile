FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod ./
COPY main.go ./
# Resolve and pin dependencies, then build a static binary.
RUN go mod tidy
RUN CGO_ENABLED=0 go build -o /secret-api .

FROM alpine:3.20

WORKDIR /app

COPY --from=builder /secret-api ./secret-api

CMD ["./secret-api"]
