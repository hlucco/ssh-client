package main

import (
	"bufio"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/hlucco/cs1515final/shared"
)

func main() {

	fmt.Println("os args: ", os.Args)

	if len(os.Args) != 2 {
		fmt.Println("Usage: go run client.go <user@server>")
		return
	}

	tokens := strings.Split(os.Args[1], "@")
	serverAddr := tokens[1]
	user := tokens[0]

	// Connect to server
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		fmt.Println("Error connecting:", err)
		return
	}
	defer conn.Close()

	// RFC 4253

	// Handshake with server
	shared.SendString("SSH-2.0-HenrySSHClient Ubuntu-4ubuntu0.3\r\n", conn)
	serverVersionString := shared.RecieveString(conn)
	fmt.Println("Server version string:", serverVersionString)
	if serverVersionString[0:4] != "SSH-" {
		fmt.Println("Server did not send a valid version string")
		return
	}

	//generate and send SSH_MSG_KEXINIT packet
	cookie := make([]byte, 16)
	rand.Read(cookie)
	kexinit_packet := shared.SSH_MSG_KEXINIT{
		Code:                                    20,
		Cookie:                                  cookie,
		Kex_algorithms:                          []string{"curve25519-sha256", "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"},
		Server_host_key_algorithms:              []string{"ssh-rsa", "ssh-dss"},
		Encryption_algorithms_client_to_server:  []string{"aes128-ctr", "aes192-ctr", "aes256-ctr"},
		Encryption_algorithms_server_to_client:  []string{"aes128-ctr", "aes192-ctr", "aes256-ctr"},
		Mac_algorithms_client_to_server:         []string{"hmac-sha2-256", "hmac-sha1"},
		Mac_algorithms_server_to_client:         []string{"hmac-sha2-256", "hmac-sha1"},
		Compression_algorithms_client_to_server: []string{"none"},
		Compression_algorithms_server_to_client: []string{"none"},
		Languages_client_to_server:              []string{},
		Languages_server_to_client:              []string{},
		First_kex_packet_follows:                0,
		Reserved:                                [4]byte{0, 0, 0, 0},
	}

	shared.EncodeAndSend(kexinit_packet, conn)

	// Deserialize the received data into a kexinit struct
	var recievedKEXINIT shared.SSH_MSG_KEXINIT
	shared.RecieveAndDecode(&recievedKEXINIT, conn)
	fmt.Printf("Recieved KEXINIT packet: %+v\n", recievedKEXINIT)

	// send dhinit packet

	private, x, y, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("Error generating private key:", err)
	}
	public := elliptic.Marshal(elliptic.P256(), x, y)

	// how to marshal back from bytes
	// public, err = ecdh.P256().NewPublicKey(public.Bytes())

	dhinit_packet := shared.SSH_MSG_KEXDH_INIT{
		Code:       30,
		Public_Key: public,
	}

	shared.EncodeAndSend(dhinit_packet, conn)

	// get response from server and compute shared secret
	var dhreply_packet shared.SSH_MSG_KEXDH_REPLY
	shared.RecieveAndDecode(&dhreply_packet, conn)
	fmt.Printf("Recieved DHREPLY packet: %+v\n", dhreply_packet)

	serverPublicKey := dhreply_packet.Public_Key
	x2, y2 := elliptic.Unmarshal(elliptic.P256(), serverPublicKey)
	if x2 == nil || y2 == nil {
		fmt.Println("Error unmarshalling client public key")
		return
	}

	sharedSecretX, _ := elliptic.P256().ScalarMult(x2, y2, private)
	sharedSecret := sharedSecretX.Bytes()
	fmt.Printf("Shared secret X: %x\n", sharedSecret)

	// send SSH_MSG_NEWKEYS to server
	newKeys := shared.SSH_MSG_NEWKEYS{
		Code: 21,
	}
	shared.EncodeAndSend(newKeys, conn)

	// all messages encrypt and mac from this point forward
	// generate AES and HMAC keys
	// do user authentication
	// send service requests in loop

	aesKey, hmacKey := shared.GenerateKeys(sharedSecret)

	// RFC 4252
	// SSH_MSG_USERAUTH_REQUEST
	var userPassword string
	fmt.Println("Enter the password for user ", user)
	fmt.Scanln(&userPassword)

	userAuthRequest := shared.SSH_MSG_USERAUTH_REQUEST{
		Code:         50,
		User_Name:    user,
		Service_Name: "ssh-connection",
		Method_Name:  "password",
		Password:     userPassword,
	}

	shared.EncryptAndSend(aesKey, hmacKey, userAuthRequest, conn)

	// recieve auth success or failure packet
	var authResponse shared.SSH_MSG_USERAUTH_FAILURE
	shared.DecryptAndVerify(aesKey, hmacKey, &authResponse, conn)

	fmt.Println("Recieved auth response: ", authResponse)

	if authResponse.Code != 52 {
		fmt.Println("Authentication failed: " + authResponse.Reason)
		return
	}

	// make nice prompt repl that lets user type commands
	// and see outputs
	reader := bufio.NewReader(os.Stdin)
	hostname := authResponse.Host_Name

	for {
		fmt.Print(user + "@" + hostname + " ~ $ ")
		text, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading input:", err)
			continue
		}

		text = strings.TrimSpace(text)
		if text == "exit" {
			exitPacket := shared.SSH_MSG_DATA{
				Code: 97,
				Data: "exit",
			}
			shared.EncryptAndSend(aesKey, hmacKey, exitPacket, conn)
			break
		}

		datapacket := shared.SSH_MSG_DATA{
			Code: 94,
			Data: text,
		}
		shared.EncryptAndSend(aesKey, hmacKey, datapacket, conn)

		var response shared.SSH_MSG_DATA
		shared.DecryptAndVerify(aesKey, hmacKey, &response, conn)

		// Process user input here
		fmt.Println(response.Data)
	}
}
