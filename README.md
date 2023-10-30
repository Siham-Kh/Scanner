# MySQL Scanner

The MySQL Scanner is a Go-based utility for detecting and retrieving basic information about MySQL instances running on a specified host and port. It performs a MySQL handshake to determine if MySQL is running and extracts server details.

## Prerequisites

- Go (Golang) installed on your system.
- Docker (if you want to test with a MySQL Docker container).

## Usage

1. Clone the repository and navigate to the project directory.

git clone <repository_url>
cd Scanner

3. Run/build the scanner by providing the target host and port as command-line arguments.
go run main.go <host> <port>

- The scanner will not remain in listening mode. It checks for the mysql server, if not connected a message "MySQL does not appear to be running on the specified host and port." will show!

- Replace <host> with the IP address of the target host and <port> with the MySQL port (typically 3306). Example: go run main.go localhost 3306


## Testing

If you don't have a mysql instance running somewhere, create one below:

1. **Start a MySQL Docker container**:
You can use the following command to create a MySQL Docker container for testing:

docker run -d --name mysql-test -e MYSQL_ROOT_PASSWORD=my-secret-pw -p 3306:3306 mysql:latest

This command creates a MySQL container with a root password "my-secret-pw" and maps port 3306 from the container to your host machine.

2. **Build and run the MySQL Scanner**:

Compile the Go code before running it:

3. **Run the scanner**:

go run main.go localhost 3306


4. **Stop and Remove the MySQL Docker Container**:

After testing, stop and remove the MySQL Docker container using the following commands:

docker stop mysql-test
docker rm mysql-test

