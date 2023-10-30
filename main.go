package main

import (
	"database/sql"
	"fmt"
	"net"
	"os"

	_ "github.com/go-sql-driver/mysql"
)

type MySQLHandshake struct {
	Host               string
	Port               int
	PacketLength       uint32
	PacketNumber       byte
	ProtocolVersion    byte
	ServerVersion      string
	ThreadID           uint32
	Salt               []byte
	ServerCapabilities uint16
	Language           byte
	AuthPluginName     string
	ServerStatus       uint16
}

func main() {

	if len(os.Args) != 3 {
		fmt.Println("Usage: mysql_scanner <host> <port>")
		os.Exit(1)
	}

	host := os.Args[1]
	port := os.Args[2]

	address := fmt.Sprintf("%s:%s", host, port)
	fmt.Println(address)

	conn, err := net.Dial("tcp", address)
	if err != nil {
		fmt.Println("MySQL does not appear to be running on the specified host and port.")
		return
	}
	defer conn.Close()

	response := make([]byte, 1024)
	_, err = conn.Read(response)
	if err != nil {
		fmt.Println("Failed to read the server greeting packet.")
		return
	}

	handshakeInfo, err := parseHandshakePacket(response)
	if err != nil {
		fmt.Println("Failed to parse the server greeting packet.")
		return
	}

	// Print the extracted information
	fmt.Printf("MySQL appears to be running on %s\n", address)
	printMySQLInstanceDetails(*handshakeInfo, host, port)

	// We can extract more inofrmation from a dummy database using the mysql package handshake
	// may be run in a goroutine if needed
	getMoreInfo(address, conn)

}

// Log initial information from the first greeting packet received from the server
func printMySQLInstanceDetails(instance MySQLHandshake, host string, port string) {
	fmt.Printf("MySQL Server Details for %s:%s\n", host, port)
	fmt.Printf("Greetung Packet Length: %d\n", instance.PacketLength)
	fmt.Printf("Greetung Packet Number: %d\n", instance.PacketNumber)
	fmt.Printf("Protocol Version: %d\n", instance.ProtocolVersion)
	fmt.Printf("Server Version: %s\n", instance.ServerVersion)
	fmt.Printf("Thread ID: %d\n", instance.ThreadID)
	fmt.Printf("Server Language: 0x%x\n", instance.Language)
	fmt.Printf("Salt: %s\n", instance.Salt)
	fmt.Printf("Server Capabilities: 0x%x\n", instance.ServerCapabilities)
	fmt.Printf("Server Status: 0x%x\n", instance.ServerStatus)
	fmt.Printf("Auth Plugin Name: %s\n", instance.AuthPluginName)

}

// PArse the first greeting packet received from the server
func parseHandshakePacket(packet []byte) (*MySQLHandshake, error) {

	handshake := &MySQLHandshake{}
	reader := 0 // Initialize a position in the byte slice

	// Packet Length (3 bytes)
	handshake.PacketLength = uint32(packet[reader]) |
		uint32(packet[reader+1])<<8 |
		uint32(packet[reader+2])<<16
	reader += 3

	// Packet Number (1 byte)
	handshake.PacketNumber = packet[reader]
	reader++

	// Protocol Version (1 byte)
	handshake.ProtocolVersion = packet[reader]
	reader++

	// Server Version (null-terminated string)
	for packet[reader] != 0 {
		handshake.ServerVersion += string(packet[reader])
		reader++
	}
	reader++

	// Connection ID (4 bytes)
	handshake.ThreadID = uint32(packet[reader]) |
		uint32(packet[reader+1])<<8 |
		uint32(packet[reader+2])<<16 |
		uint32(packet[reader+3])<<24
	reader += 4

	// Auth Plugin Data (variable size)
	saltLength := int(packet[reader])
	reader++
	fmt.Println(saltLength)

	// check MySQL version and length of this field (in wireshark 1+8)
	handshake.Salt = packet[reader : reader+8]
	reader += 8

	// Server Capabilities (2 bytes)
	handshake.ServerCapabilities = uint16(packet[reader]) |
		uint16(packet[reader+1])<<8
	reader += 2

	// Serevr Language (1 byte)
	handshake.Language = packet[reader]
	reader++

	// Server Status (2 bytes)
	handshake.ServerStatus = uint16(packet[reader]) |
		uint16(packet[reader+1])<<8
	reader += 2

	// Auth Plugin Name (null-terminated string)
	for packet[reader] != 0 {
		handshake.AuthPluginName += string(packet[reader])
		reader++
	}

	return handshake, nil
}

// I don't think this part was necessary but just in case, we can explore output of mysql package
// If we successfully connected, attempt to gather MySQL information from a dummy database
// "information_schema," is a built-in database in MySQL that doesn't require authentication.
func getMoreInfo(target string, conn net.Conn) {

	dsn := fmt.Sprintf("root:my-secret-pw@tcp(%s)/information_schema", target)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		fmt.Println("Failed to connect to MySQL:", err)
		return
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		fmt.Println("MySQL does not appear to be running on the specified host and port.")
		return
	}

	getImportantOnes(db)
}
func getServerVersion(db *sql.DB) (string, error) {
	var version string
	err := db.QueryRow("SELECT VERSION()").Scan(&version)
	if err != nil {
		return "", err
	}
	return version, nil
}

func getServerVariablesList(db *sql.DB) (map[string]string, error) {
	serverVariables := make(map[string]string)

	rows, err := db.Query("SHOW VARIABLES")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var key, value string
		err := rows.Scan(&key, &value)
		if err != nil {
			return nil, err
		}
		serverVariables[key] = value
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return serverVariables, nil
}

func getImportantOnes(db *sql.DB) {
	importantVariables := []string{
		"version",
		"datadir",
		"max_connections",
		"innodb_buffer_pool_size",
		"key_buffer_size",
		"query_cache_size",
		"innodb_log_file_size",
		"innodb_flush_log_at_trx_commit",
		"innodb_file_per_table",
		"tmpdir",
		"innodb_thread_concurrency",
		"innodb_io_capacity",
		"innodb_buffer_pool_instances",
	}
	// fmt.Printf("MySQL appears to be running on %s:%d\n", host, port)
	for _, variable := range importantVariables {
		value, err := getServerVariable(db, variable)
		if err != nil {
			fmt.Printf("%s: Error fetching value: %v\n", variable, err)
		} else {
			fmt.Printf("%s: %s\n", variable, value)
		}
	}
}

func getServerVariable(db *sql.DB, variableName string) (string, error) {
	var value string
	query := fmt.Sprintf("SHOW VARIABLES LIKE '%s'", variableName)
	err := db.QueryRow(query).Scan(&variableName, &value)
	if err != nil {
		return "", err
	}
	return value, nil
}
