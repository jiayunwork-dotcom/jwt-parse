FROM golang:1.21-alpine

WORKDIR /app
ENV GOTOOLCHAIN=local CGO_ENABLED=0

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o /app/bin/server .

EXPOSE 8080

CMD ["/app/bin/server"]
