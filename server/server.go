package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net"
	"os/exec"

	"github.com/hlucco/cs1515final/shared"
)

// Next up

// instead of trying to marshal exact binary packets, we are going to use structs
// to model the packets and then just serialize them to send between the client
// and the server.

// we will keep the old client code as a separate experiment to talk about in the
// stretch goals section as this was how we originally attempted to connect to the
// brown ssh cluster.

func handleConnection(conn net.Conn, err error) {
	// handle connection here
	fmt.Println("Client connected")

	// initial handshake with the client
	versionString := shared.RecieveString(conn)
	fmt.Println("Client version string:", versionString)
	if versionString[:4] != "SSH-" {
		fmt.Println("Error: invalid version string")
		return
	}

	shared.SendString("SSH-2.0-HenrySSHServer Ubuntu-4ubuntu0.3\r\n", conn)

	// Deserialize the received data into a kexinit struct
	var recievedKEXINIT shared.SSH_MSG_KEXINIT
	shared.RecieveAndDecode(&recievedKEXINIT, conn)
	fmt.Printf("Recieved KEXINIT packet: %+v\n", recievedKEXINIT)

	// generate the random 16 byte cookie
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

	private, x, y, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("Error generating private key:", err)
	}
	public := elliptic.Marshal(elliptic.P256(), x, y)

	var recievedDHINIT shared.SSH_MSG_KEXDH_INIT
	shared.RecieveAndDecode(&recievedDHINIT, conn)
	fmt.Printf("Recieved DHINIT packet: %+v\n", recievedDHINIT)

	clientPublicKey := recievedDHINIT.Public_Key
	x2, y2 := elliptic.Unmarshal(elliptic.P256(), clientPublicKey)
	if x2 == nil || y2 == nil {
		fmt.Println("Error unmarshalling client public key")
		return
	}

	sharedSecretX, _ := elliptic.P256().ScalarMult(x2, y2, private)
	sharedSecret := sharedSecretX.Bytes()
	fmt.Printf("Shared secret X: %x\n", sharedSecret)

	// send the server's public key
	kexdh_reply := shared.SSH_MSG_KEXDH_REPLY{
		Code:       31,
		Public_Key: public,
	}

	shared.EncodeAndSend(kexdh_reply, conn)

	var recievedNEWKEYS shared.SSH_MSG_NEWKEYS
	shared.RecieveAndDecode(&recievedNEWKEYS, conn)
	fmt.Printf("Recieved NEWKEYS packet: %+v\n", recievedNEWKEYS)

	// disconnect if key exchange was not successful
	if recievedNEWKEYS.Code != 21 {
		fmt.Println("Error: expected NEWKEYS packet")
		return
	}

	// all messages encrypted and mac from this point forward
	aesKey, hmacKey := shared.GenerateKeys(sharedSecret)

	// upon recieving userauth request, login should take place
	// and then a subprocess with a shell should be spawned
	// where the user IS the user defined by the login
	// and does not have root access

	var recievedUSERAUTH_REQUEST shared.SSH_MSG_USERAUTH_REQUEST
	shared.DecryptAndVerify(aesKey, hmacKey, &recievedUSERAUTH_REQUEST, conn)
	fmt.Printf("Recieved USERAUTH_REQUEST packet: %+v\n", recievedUSERAUTH_REQUEST)

	if !shared.VerifyPassword(recievedUSERAUTH_REQUEST.User_Name, recievedUSERAUTH_REQUEST.Password) {
		failurePacket := shared.SSH_MSG_USERAUTH_FAILURE{
			Code:      51,
			Host_Name: shared.GetHost(),
			Reason:    "Invalid password",
		}

		shared.EncryptAndSend(aesKey, hmacKey, failurePacket, conn)
		fmt.Println("Error: invalid password")
		return
	}

	successPacket := shared.SSH_MSG_USERAUTH_SUCCESS{
		Code:      52,
		Host_Name: shared.GetHost(),
	}

	shared.EncryptAndSend(aesKey, hmacKey, successPacket, conn)

	username := recievedUSERAUTH_REQUEST.User_Name

	// spawn a shell for the
	// user to interact with then just listen for commands
	for {
		var dataPacket shared.SSH_MSG_DATA = shared.SSH_MSG_DATA{}
		shared.DecryptAndVerify(aesKey, hmacKey, &dataPacket, conn)
		fmt.Printf("Recieved DATA packet: %+v\n", dataPacket)

		if dataPacket.Code == 97 {
			fmt.Println("Recieved EOF packet, closing connection")
			break
		}

		cmd := exec.Command("su", username, "-c", dataPacket.Data)

		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Println(err)
		}

		responsePacket := shared.SSH_MSG_DATA{
			Code: 94,
			Data: string(output),
		}

		shared.EncryptAndSend(aesKey, hmacKey, responsePacket, conn)
	}
}

func main() {
	// Listen for incoming connections
	listener, err := net.Listen("tcp", "0.0.0.0:2222")
	if err != nil {
		fmt.Println("Failed to listen on port 2222:", err)
		return
	}

	fmt.Println("Listening on port 2222")

	// Accept incoming connections and handle them in a new goroutine
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Failed to accept incoming connection:", err)
			continue
		}

		go handleConnection(conn, err)
	}
}
