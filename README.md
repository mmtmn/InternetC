### Features

- **TCP/IP Communication**: Simple TCP client and server.
- **DNS Queries**: Perform DNS A record lookups using `ldns`.
- **Secure Communication**: TLS-encrypted TCP client and server using OpenSSL.
- **Simulated BGP Interaction**: Basic simulation of BGP route announcement.

### Requirements

- GCC Compiler
- OpenSSL Library
- ldns Library

### Installation

1. **Install Dependencies**:
   ```bash
   sudo apt-get update
   sudo apt-get install gcc libssl-dev libldns-dev
   ```

2. **Download the Repository**:
   ```bash
   git clone https://github.com/yourusername/InternetC.git
   cd InternetC
   ```

### Compilation

1. **Compile the Program**:
   ```bash
   gcc -o main main.c -lssl -lcrypto -lldns
   ```

### Running the Program

1. **Run the Program**:
   ```bash
   ./main
   ```

### Usage

The program demonstrates the following functionalities:

1. **TCP/IP Communication**:
   - A TCP server listens on port 12345.
   - A TCP client connects to the server, sends a message, and receives an echo response.

2. **DNS Queries**:
   - Perform DNS A record lookup for a specified domain (`example.com`).

3. **Secure Communication with TLS**:
   - A TLS server listens on port 12346 using certificates (`server-cert.pem`, `server-key.pem`).
   - A TLS client connects to the server, sends a message, and receives an echo response.

4. **Simulated BGP Interaction**:
   - Simulates the announcement of a BGP route.

### Certificate Files

Ensure you have the appropriate certificate files (`server-cert.pem`, `server-key.pem`) in the same directory as the program for the TLS communication to work.

### Example Output

```bash
TCP Server listening on port 12345...
Received: Hello from client
TLS Server listening on port 12346...
Received: Hello from secure client
example.com has IP address 93.184.216.34
Received from server: Hello from client
Received from server: Hello from secure client
Simulating BGP route announcement:
Announcing route: 203.0.113.0/24
```

