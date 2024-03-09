import socket

# Create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Define the WebSocket server address and port
server_address = ('104.26.6.171', 80)

# Connect to the WebSocket server
s.connect(server_address)

# Send the WebSocket header request
header = b"GET / HTTP/1.1\r\n" \
     b"Host: wstun.ikhwanperwira.my.id\r\n" \
     b"Upgrade: websocket\r\n" \
     b"Connection: Upgrade\r\n" \
     b"Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n" \
     b"Sec-WebSocket-Version: 13\r\n\r\n"
s.send(header)

# Receive and print the response
response = s.recv(1024)
print(response.decode())

# Get user input and send it to the WebSocket server indefinitely
while True:
  try:
    user_input = input("Enter your message: ")
    s.send(user_input.encode())
    # Receive and print the response from the WebSocket server
    response = s.recv(1024)
    print(response.decode())
    
    # Check if the server closed the connection
    if not response:
      print("Server closed the connection")
      break
    
  except KeyboardInterrupt:
    break

# Close the socket
s.close()