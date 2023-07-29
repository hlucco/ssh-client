# CSCI 1515 Final Project - Mock SSH Protocol

This repository contains mock SSH client and server modules, as well as a draft of an RFC compliant SSH client and a shared utility package. This project has been implemented as a final project for Brown CSCI 1515 Applied Cryptography Spring 2023.

## Installation

Go version 1.19 or higher is recommended for building and running. This project was developed using Go 1.20.3.

Clone:

`git clone https://github.com/your-username/toy-ssh-client-server.git`

Build Client:

`cd ./client && go build client.go`

Build Server:

`docker build -t sshserver .`

## Usage

### Server

The server is meant to be run inside of a docker container to simulate a remote system that the client connects to. To run the docker container containing the server:

`docker run -p 2222:2222 --privileged sshserver`

This will expose the server's port so that the client can connect to it. The `--privileged` flag is used so that server can run commands using the proper permissions for the authenticated user.

### Client

To connect to the server using the client, use the following command from the `./client` directory:

`./client <user>@localhost:2222`

Replace `<user>` with the user on the server you are want to login as. For the purposes of this project the users were preloaded on to the server and are initialized in the Dockerfile. The user table is:

```Go
users := map[string]string {
    "henry":  "guest",
    "katara": "water",
}
```

In the format of `<username> : <password>`

Once you are connected, you can run commands on the server.

## RFC Client

The partially implemented RFC client is included in the `brownsshclient` directory. This client can get as far as the `SSH_MSG_KEXINIT` packet. To build and run:

`go build sshclient.go`

`./sshclient`

