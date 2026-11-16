# syntax=docker/dockerfile:1
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/dns-auditor ./cmd/dns-auditor

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/dns-auditor /dns-auditor
USER 65532:65532
EXPOSE 6000 8080
ENTRYPOINT ["/dns-auditor"]
CMD ["serve"]
