FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum main.go ./
COPY internal/ internal/
ARG TARGETOS TARGETARCH TARGETVARIANT VERSION=dev
RUN env CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    ${TARGETVARIANT:+GOARM=${TARGETVARIANT#v}} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /awg-proxy .

FROM scratch
COPY --from=build /awg-proxy /awg-proxy
ENTRYPOINT ["/awg-proxy"]
