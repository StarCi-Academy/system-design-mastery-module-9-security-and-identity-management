FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod ./
COPY *.go ./

RUN CGO_ENABLED=0 go build -o /waf-gateway .

FROM alpine:3.20

WORKDIR /app

COPY --from=builder /waf-gateway ./waf-gateway

CMD ["./waf-gateway"]
