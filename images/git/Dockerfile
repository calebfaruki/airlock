FROM alpine:3.21
LABEL dev.airlock.tools='["git"]'
RUN apk add --no-cache git openssh-client
ARG TARGETARCH
COPY airlock-runtime-linux-${TARGETARCH} /usr/local/bin/airlock-runtime
RUN chmod +x /usr/local/bin/airlock-runtime
ENTRYPOINT ["airlock-runtime"]
