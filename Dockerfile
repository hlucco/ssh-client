FROM alpine:latest

RUN apk update && apk add --no-cache shadow

RUN apk add --no-cache go

WORKDIR /app

EXPOSE 2222

COPY . .
RUN go build -o server/sshserver server/server.go
RUN adduser -D -g '' henry \
    && echo 'henry:guest' | chpasswd
RUN adduser -D -g '' katara \
    && echo 'katara:water' | chpasswd

CMD ["./server/sshserver"]
