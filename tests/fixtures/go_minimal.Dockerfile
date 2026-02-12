FROM golang:1.21-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /bin/server ./cmd/server

FROM scratch
COPY --from=build /bin/server /server
EXPOSE 8080
USER 65534
ENTRYPOINT ["/server"]
