FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /postern .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /postern /usr/local/bin/postern
EXPOSE 8080
ENTRYPOINT ["postern"]
