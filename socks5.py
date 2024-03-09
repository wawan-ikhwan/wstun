from threading import Thread
import socket

BUFFER_SIZE = 4096

SOCKS5_SERVER_IP = '192.168.43.248'
SOCKS5_SERVER_PORT = 1080

CF_IP = '104.26.6.171'
CF_PORT = 80

def construct_ws_request(DST_ADDR: str, DST_PORT: int):
  return b"GET / HTTP/1.1\r\n" \
  b"Host: wstun.ikhwanperwira.my.id\r\n" \
  b"Tunnel: TCP|"+DST_ADDR.encode('ascii')+b"|"+str(DST_PORT).encode('ascii')+b"\r\n" \
  b"Upgrade: websocket\r\n" \
  b"Connection: Upgrade\r\n" \
  b"Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n" \
  b"Sec-WebSocket-Version: 13\r\n\r\n"

def parse_socks5_handshake(data: bytes):
  if data[0] != 5:
    raise Exception(f'Invalid version when parsing socks5 request: {data[0]}')

  CMD: bytes = data[1:2]
  ATYP: bytes = data[3:4]
  PORT: bytes = data[-2:]
  if ATYP == b'\x01':
    DST_ADDR_LEN = 4
    DST_ADDR: bytes = data[4:4+DST_ADDR_LEN]
  elif ATYP == b'\x03':
    DST_ADDR_LEN: int = data[4]
    DST_ADDR = data[5:5+DST_ADDR_LEN]
  elif ATYP == b'\x04':
    DST_ADDR_LEN: int = 6
    DST_ADDR = data[4:4+DST_ADDR_LEN]
  else:
    raise Exception(f'Invalid ATYP: {ATYP}')

  DST_ADDR_RAW: bytes = data[4:-2] 
  
  return CMD, ATYP, DST_ADDR_LEN, DST_ADDR, PORT, DST_ADDR_RAW

def handshake_websocket(ATYP: bytes, DST_ADDR: bytes, DST_PORT: bytes):
    
  wsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

  wsock.connect((CF_IP, CF_PORT))

  if ATYP == b'\x01':
    DST_ADDR = socket.inet_ntoa(DST_ADDR)
  else:
    DST_ADDR = DST_ADDR.decode('ascii')
  DST_PORT = int.from_bytes(DST_PORT, 'big')

  try:
    wsreq: bytes = construct_ws_request(DST_ADDR, DST_PORT)
    if wsock.send(wsreq) != len(wsreq):
      raise Exception('Failed to send websocket request.')
    
    wsres: bytes = wsock.recv(BUFFER_SIZE)
    if not b"101 Switching Protocols" in wsres[:64]:
      raise Exception(f"Websocket server didn't return 101 Switching Protocols! {wsres}")
    
    print('Switching protocol accepted from websocket server!')
  except Exception as e:
    print(__name__, e)
    raise e

  return wsock
    
def handshake_socks5(csock: socket.socket):

  # Check method request
  if csock.recv(BUFFER_SIZE)  != b'\x05\x01\x00':
    raise Exception('Invalid method request.')
  
  # Send method response
  if csock.send(b'\x05\x00') != 2:
    raise Exception('Failed to send method response.')
  
  # Parse the request
  CMD, ATYP, DST_ADDR_LEN, DST_ADDR, PORT, DST_ADDR_RAW= parse_socks5_handshake(csock.recv(BUFFER_SIZE))
  if CMD != b'\x01':
    raise Exception(f'Currently CMD other than CONNECT is not supported! {CMD}')
  
  if ATYP == b'\x04':
    raise Exception('Currently ATYP IPv6 is not supported!')
  
  # Handshake with websocket server
  print('Connecting...', CMD, ATYP, DST_ADDR_LEN, DST_ADDR, PORT, DST_ADDR_RAW)
  wsock: socket.socket = handshake_websocket(ATYP, DST_ADDR, PORT)

  REPLY_DATA = b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00'
  
  # Send handshake response
  if csock.send(REPLY_DATA) != 10:
    raise Exception(f'Failed to send socks5 handshake response: {REPLY_DATA}')
  
  return wsock

def handle_socks5client(csock: socket.socket, caddr: tuple):
  try:
    wsock = handshake_socks5(csock)
  except Exception as e:
    csock.close()
    del csock
    print(__name__, e)
    return
  
  relay_data(csock, wsock)

def relay_data(src: socket.socket, dst: socket.socket):
  try:
    while 1:
      data: bytes = src.recv(BUFFER_SIZE)
      dst.sendall(data)
      if not data:
        print('No data from client!')
        break

      data: bytes = dst.recv(BUFFER_SIZE)
      src.sendall(data)
      if not data:
        print('No data from server!')
        break
      
  except Exception as e:
    print(f"Error occurred while relaying data, possibly closed connection: {e}")
  finally:
    src.close()
    dst.close()
    del src
    del dst

def main():
  socks5server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  socks5server.bind((SOCKS5_SERVER_IP, SOCKS5_SERVER_PORT))
  socks5server.listen(5)

  while 1:
    try:
      csock, caddr = socks5server.accept()
      Thread(target=handle_socks5client, args=(csock, caddr, )).start()
    except Exception as e:
      print(__name__, e)
      break

if __name__ == '__main__':
  main()