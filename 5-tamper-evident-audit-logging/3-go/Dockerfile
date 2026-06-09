FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
RUN CGO_ENABLED=0 go build -o /audit-api ./main.go

FROM alpine:3.20

WORKDIR /app
COPY --from=builder /audit-api ./audit-api

CMD ["./audit-api"]
