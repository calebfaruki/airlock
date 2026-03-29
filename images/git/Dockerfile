FROM alpine:3.21
RUN apk add --no-cache git openssh-client
ARG TARGETARCH
COPY airlock-agent-linux-${TARGETARCH} /usr/local/bin/airlock-agent
RUN chmod +x /usr/local/bin/airlock-agent
ENTRYPOINT ["airlock-agent"]
