import socket
import hashlib
import base64

# Function to generate the WebSocket handshake response
def generate_handshake_response(request):
  key_name = "Sec-WebSocket-Key"
  start_index = request.find(key_name)
  end_index = request.find("\r\n", start_index + len(key_name))
  key = request[start_index + len(key_name):end_index].strip()

  print(key)

  response_key = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
  response = "HTTP/1.1 101 Switching Protocols\r\n"
  response += "Upgrade: websocket\r\n"
  response += "Connection: Upgrade\r\n"
  response += "Sec-WebSocket-Accept: " + response_key + "\r\n\r\n"
  return response

# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Set the host and port
host = '127.0.0.1'
port = 3333

# Bind the socket to the host and port
server_socket.bind((host, port))

# Listen for incoming connections
server_socket.listen(1)

print("WebSocket server is listening on {}:{}".format(host, port))

while True:
  client_socket, client_address = server_socket.accept()
  print("Client connected:", client_address)

  print("Receiving handshake request...")
  request = client_socket.recv(1024).decode()
  print("Received handshake request:\n", request)

  print("Generating handshake response...")
  response = generate_handshake_response(request)
  print("Generated handshake response:\n", response)
  if response:
    client_socket.send(response.encode())

    # Now the WebSocket connection is established
    # You can start sending and receiving WebSocket messages here
    
    while True:
      # Receive data from the client
      data = client_socket.recv(1024).decode()
      print("Received data:", data)
      
      # Check if the received data is empty, indicating that the client has closed the connection
      if not data:
        print("Client closed the connection")
        break
      
      # Echo the received data back to the client
      client_socket.send(data.encode())
      print("Sent data:", data)

  # Close the client connection
  client_socket.close()