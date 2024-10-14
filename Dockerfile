ARG GOOS
ARG GOARCH
ARG VERSION
ARG BUILDHASH
ARG BUILDTIME

FROM golang:latest AS builder
ADD . /yamat/
WORKDIR /yamat/

ENV GOOS=${GOOS}
ENV GOARCH=${GOARCH}
ARG VERSION=${VERSION}
ARG BUILDHASH=${BUILDHASH}
ARG BUILDTIME=${BUILDTIME}
ENV LDFLAGS="-s -w \
	-X \"main.Version="$VERSION"\" \
	-X \"main.BuildHash="$BUILDHASH"\" \
	-X \"main.BuildTime="$BUILDTIME"\" \
"

RUN go mod download
RUN CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} go build -o yamat -ldflags "${LDFLAGS}" .

# final stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /yamat/yamat ./
RUN chmod +x ./yamat
ENTRYPOINT ["./yamat"]