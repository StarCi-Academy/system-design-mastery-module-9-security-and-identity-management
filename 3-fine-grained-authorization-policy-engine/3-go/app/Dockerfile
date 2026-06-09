FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 go build -o /server main.go

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /server /server
EXPOSE 3000
CMD ["/server"]
