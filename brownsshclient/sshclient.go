package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
)

const (
	SSH_MSG_KEXINIT     = 20
	SSH_MSG_NEWKEYS     = 21
	SSH_MSG_KEXDH_INIT  = 30
	SSH_MSG_KEXDH_REPLY = 31
)

// create an ssh packet with the given payload
func make_kexinit_packet() []byte {
	cookie := make([]byte, 16)
	rand.Read(cookie)

	key_exchange_list := "curve25519-sha256, diffie-hellman-group-exchange-sha256"
	server_host_key_list := "ssh-rsa"
	encryption_client_to_server_list := "aes256-ctr"
	encryption_server_to_client_list := "aes256-ctr"
	mac_client_to_server_list := "hmac-sha2-256"
	mac_server_to_client_list := "hmac-sha2-256"
	compression_client_to_server_list := "none"
	compression_server_to_client_list := "none"
	languages_client_to_server_list := ""
	languages_server_to_client_list := ""

	// build the packet
	var packet bytes.Buffer
	packet.WriteByte(SSH_MSG_KEXINIT) // SSH_MSG_KEXINIT
	packet.Write(cookie)

	binary.Write(&packet, binary.BigEndian, uint32(len(key_exchange_list))) // reserved field
	packet.WriteString(key_exchange_list)                                   // key exchange algorithms

	binary.Write(&packet, binary.BigEndian, uint32(len(server_host_key_list))) // reserved field
	packet.WriteString(server_host_key_list)                                   // server host key algorithms

	binary.Write(&packet, binary.BigEndian, uint32(len(encryption_client_to_server_list))) // reserved field
	packet.WriteString(encryption_client_to_server_list)                                   // encryption algorithms client to server

	binary.Write(&packet, binary.BigEndian, uint32(len(encryption_server_to_client_list))) // reserved field
	packet.WriteString(encryption_server_to_client_list)                                   // encryption algorithms server to client

	binary.Write(&packet, binary.BigEndian, uint32(len(mac_client_to_server_list))) // reserved field
	packet.WriteString(mac_client_to_server_list)                                   // mac algorithms client to server

	binary.Write(&packet, binary.BigEndian, uint32(len(mac_server_to_client_list))) // reserved field
	packet.WriteString(mac_server_to_client_list)                                   // mac algorithms server to client

	binary.Write(&packet, binary.BigEndian, uint32(len(compression_client_to_server_list))) // reserved field
	packet.WriteString(compression_client_to_server_list)                                   // compression algorithms client to server

	binary.Write(&packet, binary.BigEndian, uint32(len(compression_server_to_client_list))) // reserved field
	packet.WriteString(compression_server_to_client_list)                                   // compression algorithms server to client

	binary.Write(&packet, binary.BigEndian, uint32(len(languages_client_to_server_list))) // reserved field
	packet.WriteString(languages_client_to_server_list)                                   // languages client to server

	binary.Write(&packet, binary.BigEndian, uint32(len(languages_server_to_client_list))) // reserved field
	packet.WriteString(languages_server_to_client_list)                                   // languages server to client

	packet.WriteByte(0)                                // first kex packet follows
	binary.Write(&packet, binary.BigEndian, uint32(0)) // reserved field

	return packet.Bytes()
}

func buildPacket(payload []byte) []byte {
	// Calculate packet length
	packetLength := uint32(len(payload) + 5) // Payload + packet_length(4 bytes) + padding_length(1 byte)

	// Create packet buffer
	packetBuffer := new(bytes.Buffer)

	// Write packet length
	binary.Write(packetBuffer, binary.BigEndian, packetLength)

	// Write padding length (1 byte)
	paddingLength := 4
	packetBuffer.WriteByte(byte(paddingLength))

	// Write payload
	packetBuffer.Write(payload)

	packetBuffer.Write(make([]byte, paddingLength)) // Write padding

	// Return packet
	return packetBuffer.Bytes()
}

func make_kexdhinit_packet(public_key [32]byte) []byte {
	var payload bytes.Buffer

	binary.Write(&payload, binary.BigEndian, uint8(SSH_MSG_KEXDH_INIT))
	binary.Write(&payload, binary.BigEndian, uint32(len(public_key)))
	binary.Write(&payload, binary.BigEndian, public_key)

	return payload.Bytes()
}

func main() {

	// server_addr := "localhost:2222"
	server_addr := "ssh.cs.brown.edu:22"
	// fmt.Printf("Public key: %v\n", public_key)

	conn, err := net.Dial("tcp", server_addr)
	if err != nil {
		fmt.Println("Error connecting:", err)
		return
	}
	defer conn.Close()

	version_string := []byte("SSH-2.0-HenrySSHClient Ubuntu-4ubuntu0.3\r\n")
	_, err = conn.Write(version_string)

	if err != nil {
		fmt.Println("Error sending version string:", err)
		return
	}

	fmt.Println("Version string sent. Waiting for server response.")

	scanner := bufio.NewScanner(conn)
	var server_version string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "SSH-") {
			server_version = line
			break
		}
	}
	if !strings.HasPrefix(server_version, "SSH-2.") {
		fmt.Printf("Server is not compatible with SSH protocol version 2\n")
		return
	}

	fmt.Printf("Server version: %s\n", server_version)

	kexinit_packet := buildPacket(make_kexinit_packet())
	_, err = conn.Write(kexinit_packet)
	if err != nil {
		fmt.Println("Error sending kexinit packet:", err)
		return
	}

	// var server_public_key string
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Printf("Server sent: %s\n", line)
	}

	var private_key [32]byte
	var public_key [32]byte

	io.ReadFull(rand.Reader, private_key[:])

	fmt.Printf("Private Key: %x\n", private_key[:])
	fmt.Printf("Public Key: %x\n", public_key[:])

	ssh_msg_kexdh_init_packet := buildPacket(make_kexdhinit_packet(public_key))
	fmt.Println("packet to send: ", ssh_msg_kexdh_init_packet)
	_, err = conn.Write(ssh_msg_kexdh_init_packet)
	if err != nil {
		fmt.Println("Error sending packet:", err)
		return
	}

	fmt.Println("packet sent")

	for scanner.Scan() {
		line := scanner.Text()
		fmt.Printf("Server sent: %s\n", line)
	}

}
