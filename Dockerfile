FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION}" -o /postern .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /postern /usr/local/bin/postern
EXPOSE 8080 9090
ENTRYPOINT ["postern"]
CMD ["serve"]
