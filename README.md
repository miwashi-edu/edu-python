# edu-python

## Port Scanning

```python
import socket

def is_port_open(host, port):
    """Check if a port is open on the given host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Timeout of 1 second
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except socket.error:
        return False

def scan_ports(host, start_port, end_port):
    """Scan a range of ports on a host."""
    print(f"Scanning ports on {host} from {start_port} to {end_port}")
    for port in range(start_port, end_port + 1):
        if is_port_open(host, port):
            print(f"Port {port} is open")
        else:
            print(f"Port {port} is closed")

# Example usage
target_host = "192.168.1.1"  # Replace with the target host IP
start_port = 1
end_port = 100  # Scanning first 100 ports

scan_ports(target_host, start_port, end_port)

```


## Network scanning

```python
import socket
import ipaddress

def is_port_open(host, port):
    """Check if a port is open on the given host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)  # Timeout of 0.5 second
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except socket.error:
        return False

def scan_host(host, ports):
    """Scan a host for open ports."""
    print(f"Scanning {host}")
    for port in ports:
        if is_port_open(host, port):
            print(f"Port {port} is open on {host}")

def scan_network(network, ports):
    """Scan a network for active hosts and open ports."""
    for ip in ipaddress.IPv4Network(network):
        scan_host(str(ip), ports)

# Example usage
network = "192.168.1.0/24"  # Replace with your network
ports_to_scan = [22, 80, 443]  # Replace with your ports of interest

scan_network(network, ports_to_scan)
```



## DNS

```bash
pip install dnspython
```

```python
import dns.resolver

# Function to get A record (IP address)
def get_a_record(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        for ipval in result:
            print('A Record:', ipval.to_text())
    except Exception as e:
        print('Error:', e)

# Function to get MX record (Mail server)
def get_mx_record(domain):
    try:
        result = dns.resolver.resolve(domain, 'MX')
        for mail_server in result:
            print('MX Record:', mail_server.exchange.to_text())
    except Exception as e:
        print('Error:', e)

# Function to get NS record (Name servers)
def get_ns_record(domain):
    try:
        result = dns.resolver.resolve(domain, 'NS')
        for nameserver in result:
            print('NS Record:', nameserver.to_text())
    except Exception as e:
        print('Error:', e)

# Test the functions with a domain
domain = 'example.com'
print(f"DNS records for {domain}:")
get_a_record(domain)
get_mx_record(domain)
get_ns_record(domain)
```

## ARP

```bash
pip install scapy
```

```python
from scapy.all import sniff, ARP

def arp_display(pkt):
    if pkt.haslayer(ARP):
        if pkt[ARP].op == 1:  # who-has (request)
            return f"Request: {pkt[ARP].psrc} is asking about {pkt[ARP].pdst}"
        if pkt[ARP].op == 2:  # is-at (response)
            return f"*Response: {pkt[ARP].hwsrc} has address {pkt[ARP].psrc}"

print("Sniffing ARP packets...")
sniff(prn=arp_display, filter="arp", store=0, count=0)
```

## TCP Lyssnare

```python
import socket

def start_server(ip, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, port))
    server_socket.listen(1)
    print(f"Listening on {ip}:{port}")

    client_socket, client_address = server_socket.accept()
    print(f"Connection from {client_address}")

    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        print(f"Received: {data.decode()}")
        client_socket.sendall(data)

    client_socket.close()
    server_socket.close()

# Run the server
server_ip = '192.168.0.3'
server_port = 12345
start_server(server_ip, server_port)
```

## TCP Sändare

```python
import socket

def send_message(ip, port, message):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((ip, port))
    client_socket.sendall(message.encode())

    response = client_socket.recv(1024)
    print(f"Received: {response.decode()}")

    client_socket.close()

# Send a message
server_ip = '192.168.0.3'
server_port = 12345
message = "Hello, Server!"
send_message(server_ip, server_port, message)
```

## UDP Lyssnare

```python
import socket

def start_udp_server(ip, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((ip, port))
    print(f"UDP Server listening on {ip}:{port}")

    while True:
        data, client_address = server_socket.recvfrom(1024)
        if not data:
            break
        print(f"Received: {data.decode()} from {client_address}")
        server_socket.sendto(data, client_address)

    server_socket.close()

# Run the server
server_ip = '192.168.0.3'
server_port = 12345
start_udp_server(server_ip, server_port)
```

## UDP Sändare

```python
import socket

def send_udp_data(ip, port, message):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # Send data
        client_socket.sendto(message.encode(), (ip, port))
        print(f"Sent: {message} to {ip}:{port}")

        # Receive response
        data, server = client_socket.recvfrom(1024)
        print(f"Received: {data.decode()} from {server}")

    finally:
        client_socket.close()

# Example usage
server_ip = '192.168.0.3'
server_port = 12345
message = "Hello, UDP Server!"
send_udp_data(server_ip, server_port, message)

```


## TLS Communication

```bash
pip install cryptography
```

```python
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64

# Generate an RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Extract public key from the private key
public_key = private_key.public_key()

# Encrypting the private key with a passphrase
passphrase = b'secret'
pem_private_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
)

# Public key in PEM format
pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Encrypt a message with the private key
plaintext = "hemligt hemligt"
ciphertext = private_key.encrypt(
    plaintext.encode(),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Decrypt the message with the public key
decrypted_message = public_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("Private Key (PEM format):\n", pem_private_key.decode())
print("Public Key (PEM format):\n", pem_public_key.decode())
print("Encrypted Message (Base64 Encoded):\n", base64.b64encode(ciphertext).decode())
print("Decrypted Message:\n", decrypted_message.decode())
```


## Brute force attack on hashcode

```bash
pip install hashlib
pip install itertools
```


```python
import hashlib
import itertools

# The secret password and its MD5 hash
password = "abaa"
secret_hash = hashlib.md5(password.encode()).hexdigest()

# Function to compare the hash of a given password with the secret hash
def hack(test_password):
    test_hash = hashlib.md5(test_password.encode()).hexdigest()
    if secret_hash == test_hash:
        print(f"Match found: {test_password}")
        return True
    return False

# Brute force approach
chars = ['a', 'b']
for combo in itertools.product(chars, repeat=len(password)):
    test_pass = ''.join(combo)
    if hack(test_pass):
        break
```

```
from scapy.all import ARP, Ether, srp
import sys

def arp_scan(ip_range):
    """
    Performs an ARP scan on the specified IP range.

    :param ip_range: String, the IP range to scan, e.g., "192.168.1.1/24".
    :return: None
    """
    # Create an Ether and ARP packet
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    
    # Send the packet and capture the response
    answered, _ = srp(arp_request, timeout=2, verbose=False)

    # Process the response
    for sent, received in answered:
        print(received.psrc)  # Print the discovered IP addresses

# Take the IP range from command line arguments
if len(sys.argv) > 1:
    target_ip_range = sys.argv[1]
else:
    print("Usage: python arp_scan.py <IP range>")
    sys.exit(1)

arp_scan(target_ip_range)
```

