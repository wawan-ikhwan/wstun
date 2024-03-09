from threading import Thread
import socket

BUFFER_SIZE = 4096

WEBSOCKET_SERVER_IP = '192.168.43.248'
WEBSOCKET_SERVER_PORT = 8000

WEBSOCKET_REPLY = b"HTTP/1.1 101 Switching Protocols\r\n" \
        b"Upgrade: websocket\r\n" \
        b"Connection: Upgrade\r\n" \
        b"Sec-WebSocket-Accept: HSmrc0sMlYUkAGmm5OPpG2HaGWk=\r\n\r\n"
WEBSOCKET_REPLY_LEN: int = len(WEBSOCKET_REPLY)

def parsing_header_request(data: bytes):
  '''
  Return: DST_PROTO (str), DST_ADDR (str), DST_PORT (int)
  '''
  tunnel: bytes = data.split(b"Tunnel: ")[1].strip().split(b"\r\n")[0]
  splitted = tunnel.split(b'|')
  DST_PROTO: str = splitted[0].decode('ascii')
  DST_ADDR: str = splitted[1].decode('ascii')
  DST_PORT = int(splitted[2].decode('ascii'))
  return DST_PROTO, DST_ADDR, DST_PORT

def handshake_tcp(DST_ADDR: str, DST_PORT: int):
  tsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  try:
    tsock.connect(("192.168.43.248", DST_PORT))
  except Exception as e:
    raise Exception(f'Failed to connect to destination: {e}')
  return tsock

def handshake_websocket(csock: socket.socket):
  data: bytes = csock.recv(BUFFER_SIZE)
  if not data:
    raise Exception('No data received from client!')
  
  if not b"Tunnel: " in data:
    raise Exception(f'Not a tunneling request: {data}')
  
  DST_PROTO, DST_ADDR, DST_PORT = parsing_header_request(data)

  if DST_ADDR != 'example.com':
    raise Exception("Not desired addr!")
  
  print(f"Connecting to {DST_ADDR}:{DST_PORT}")
  tsock = handshake_tcp(DST_ADDR, DST_PORT)
  print("Connected:", tsock)

  if csock.send(WEBSOCKET_REPLY) != WEBSOCKET_REPLY_LEN:
    raise Exception('Failed to send websocket reply!')

  return tsock

def handle_websocketclient(csock: socket.socket, caddr: tuple):
  try:
    tsock = handshake_websocket(csock)
  except Exception as e:
    csock.close()
    del csock
    print(__name__, e)
    return
  
  relay_data(csock, tsock)

def relay_data(src: socket.socket, dst: socket.socket):
  try:
    while 1:
      data: bytes = src.recv(BUFFER_SIZE)
      if not data:
        print('No data from client!')
        break
      # else:
      #   print('FROM CLIENT:', data)
      dst.sendall(data)

      data: bytes = dst.recv(BUFFER_SIZE)
      if not data:
        print('No data from server!')
        break
      # else:
      #   print('FROM SERVER:', data)
      src.sendall(data)
  except Exception as e:
    print(f"Error occurred while relaying data, possibly closed connection: {e}")
  finally:
    src.close()
    dst.close()
    del src
    del dst


def main():
  wsserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  wsserver.bind((WEBSOCKET_SERVER_IP, WEBSOCKET_SERVER_PORT))
  wsserver.listen(5)

  while 1:
    csock, caddr = wsserver.accept()
    print(f'Connected to {caddr}')
    Thread(target=handle_websocketclient, args=(csock, caddr, )).start()

if __name__ == '__main__':
  main()