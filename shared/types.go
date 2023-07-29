package shared

type Packet interface{}

type SSH_MSG_KEXINIT struct {
	Packet
	Code                                    byte
	Cookie                                  []byte
	Kex_algorithms                          []string
	Server_host_key_algorithms              []string
	Encryption_algorithms_client_to_server  []string
	Encryption_algorithms_server_to_client  []string
	Mac_algorithms_client_to_server         []string
	Mac_algorithms_server_to_client         []string
	Compression_algorithms_client_to_server []string
	Compression_algorithms_server_to_client []string
	Languages_client_to_server              []string
	Languages_server_to_client              []string
	First_kex_packet_follows                byte
	Reserved                                [4]byte
}

type SSH_MSG_KEXDH_INIT struct {
	Packet
	Code       byte
	Public_Key []byte
}

type SSH_MSG_KEXDH_REPLY struct {
	Packet
	Code       byte
	Public_Key []byte
}

type SSH_MSG_NEWKEYS struct {
	Packet
	Code byte
}

type SSH_MSG_USERAUTH_REQUEST struct {
	Packet
	Code         byte
	User_Name    string
	Service_Name string
	Method_Name  string
	Password     string
}

type SSH_MSG_USERAUTH_SUCCESS struct {
	Packet
	Code      byte
	Host_Name string
}

type SSH_MSG_USERAUTH_FAILURE struct {
	Packet
	Code      byte
	Host_Name string
	Reason    string
}

type SSH_MSG_DATA struct {
	Packet
	Code byte
	Data string
}
