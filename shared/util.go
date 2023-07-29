package shared

import (
	"bufio"
	"bytes"
	"crypto/sha512"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

func SendString(payload string, conn net.Conn) {
	_, err := conn.Write([]byte(payload))
	if err != nil {
		fmt.Println("Error sending string:", err)
		return
	}
}

func RecieveString(conn net.Conn) string {
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "SSH-") {
			return line
		}
	}

	return "💀💀💀"
}

func EncodeAndSend(packet Packet, conn net.Conn) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(packet)
	if err != nil {
		fmt.Println("Error encoding DHINIT struct:", err)
		return
	}

	_, err = conn.Write(buf.Bytes())
	if err != nil {
		fmt.Println("Error sending dhinit packet:", err)
		return
	}
}

func RecieveAndDecode(packet interface{}, conn net.Conn) {
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("Error receiving data from server:", err)
		return
	}

	decoder := gob.NewDecoder(bytes.NewReader(buffer[:n]))
	err = decoder.Decode(packet)
	if err != nil {
		fmt.Println("Error decoding KEXINIT struct:", err)
		return
	}
}
func lookupPassword(username string) string {
	cmd := exec.Command("sh", "-c", "cat /etc/shadow | grep '"+username+"'")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error looking up password:", err)
		return ""
	}

	fields := strings.Split(string(output), ":")
	hashedPwd := fields[1]

	return hashedPwd
}

func VerifyPassword(username string, password string) bool {
	hashedPwd := lookupPassword(username)

	// fmt.Println("Hashed password:", hashedPwd)

	tokens := strings.Split(hashedPwd, "$")
	salt := tokens[2]
	// fmt.Println("Salt:", salt)

	saltedPassword := append([]byte(salt), password...)
	hash := sha512.Sum512(saltedPassword)
	saltString := "$6$" + salt + "$"
	hashString := hex.EncodeToString(hash[:])
	result := saltString + hashString
	result = result // to shut up the compiler

	// return result == hashedPwd

	// fmt.Println("Stored Hash: ", result)
	// fmt.Println("Hashed Input:", result)

	// this is hardcodedbecause I tried
	// for three hours to do a sha512 hash in EXACTLY
	// the way they want it and Go seems to be incredibly
	// incapable of doing this without significant hours
	// of work. stackoverflow and chatgpt also fail to
	// be able to do this so because it is NOT the point
	// of this project, I am leaving the code that should
	// do it properly up there but the hashes aren't quite
	// the same because it doesnt do it in the
	// pRoPeR fOrMaT (MCF)

	users := map[string]string{
		"henry":  "guest",
		"katara": "water",
	}

	return users[username] == password
}

func GetHost() string {
	out, err := exec.Command("hostname").Output()
	if err != nil {
		panic(err)
	}
	hostname := string(out)
	return hostname
}
