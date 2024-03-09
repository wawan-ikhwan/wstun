import socket
from rfc1928_constants import *
from time import sleep

NUM_METHOD = 1
METHOD_REQ = VER_5 + NUM_METHOD.to_bytes(1, 'big') + METHOD_NOAUTHENTICATIONREQUIRED
METHOD_RES = VER_5 + METHOD_NOAUTHENTICATIONREQUIRED

SOCKS5_SERVER_IP = '192.168.43.248'
SOCKS5_SERVER_PORT = 9999

socks5clients: list = []

def start_ws_tunnel(DST_ADDR: str, DST_PORT: int, clientsock: socket.socket, clientaddr: tuple[str, int]):

  # Websocket client initialization...
  ws = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  wsreq: bytes = b"GET / HTTP/1.1\r\n" \
    b"Host: wstun.ikhwanperwira.my.id\r\n" \
    b"Tunnel: TCP|"+DST_ADDR.encode()+b"|"+str(DST_PORT).encode()+b"\r\n" \
    b"Upgrade: websocket\r\n" \
    b"Connection: Upgrade\r\n" \
    b"Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n" \
    b"Sec-WebSocket-Version: 13\r\n\r\n"
  ws.connect(('104.26.6.171', 80)) # Connect to Cloudflare IP
  ws.send(wsreq)
  wsres: bytes = ws.recv(1024)
  if not b"101 Switching Protocols" in wsres[:64]:
    raise Exception(f"Websocket server didn't return 101 Switching Protocols! {wsres}")
  print('Switching protocol accepted from websocket server!')
  
  while 1:
    req = clientsock.recv(4096)
    if not req:
      print('connection closed from client')
      break

    succeed = ws.send(req)
    if succeed != len(req):
      print('failed on forwarding request from client to server')
      break

    res = ws.recv(4096)
    if not res:
      print('connection closed from server')
      break

    succeed = clientsock.send(res)
    if succeed != len(res):
      print('failed on forwarding response from server to client')
      break

  print('Connection closed:', clientaddr)
  ws.close()
  clientsock.close()
  del ws
  del clientsock
  del clientaddr

def client_collector(interrupt):
  global socks5clients
  
  tcpsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  tcpsocket.bind((SOCKS5_SERVER_IP, SOCKS5_SERVER_PORT))
  tcpsocket.listen(5)

  while not interrupt.is_set():
    socks5clients.append(tcpsocket.accept())

def tcp_handler(interrupt):
  from threading import Thread
  global socks5clients

  while not interrupt.is_set():
    try:
      for client in socks5clients:
        clientsock, clientaddr = client
        method_req = clientsock.recv(1024)
        VER = method_req[0:1]
        NMETHOD = method_req[1:2]
        METHODS = method_req[2:2+int.from_bytes(NMETHOD, 'big')]
        if method_req == METHOD_REQ:
          method_res = METHOD_RES
          nbytes_sent = clientsock.send(method_res)
          if nbytes_sent != len(method_res):
            raise Exception('Failed to send method response!')
        else:
          raise Exception(f'Invalid method request! {METHOD_REQ}')
        socks5req: bytes = clientsock.recv(1024)
        VER: bytes = socks5req[0:1]
        CMD: bytes = socks5req[1:2]
        RSV: bytes = socks5req[2:3]
        ATYP = socks5req[3:4]
        if VER != VER_5:
          raise Exception('Invalid version number!')
        if CMD not in [CMD_CONNECT, CMD_BIND, CMD_UDP]:
          raise Exception('Invalid command!')
        if RSV != TCP_RSV:
          raise Exception('Invalid reserved byte!')
        
        BND_ADDR, BND_PORT = SOCKS5_SERVER_IP, SOCKS5_SERVER_PORT
        # if CMD == CMD_UDP:
        #   print('UDP request detected on:', clientaddr)
        
        if ATYP == ATYP_IPV4:
          DST_ADDR_LEN = ATYP_IPV4_LEN
          DST_ADDR = socket.inet_ntoa(socks5req[4:4+DST_ADDR_LEN])
          DST_PORT = int.from_bytes(socks5req[4+DST_ADDR_LEN:4+DST_ADDR_LEN+2], 'big')
          socks5res = VER_5 + REP_SUCCEEDED + TCP_RSV + ATYP_IPV4 + socket.inet_aton(BND_ADDR) + BND_PORT.to_bytes(2, 'big')
        elif ATYP == ATYP_IPV6:
          DST_ADDR_LEN = ATYP_IPV6_LEN
          DST_ADDR = socket.inet_ntop(socket.AF_INET6, socks5req[4:4+DST_ADDR_LEN])
          DST_PORT = int.from_bytes(socks5req[4+DST_ADDR_LEN:4+DST_ADDR_LEN+2], 'big')
          socks5res = VER_5 + REP_SUCCEEDED + TCP_RSV + ATYP_IPV4 + socket.inet_aton(BND_ADDR) + BND_PORT.to_bytes(2, 'big')
        elif ATYP == ATYP_DNS:
          DST_ADDR_LEN = int.from_bytes(socks5req[4:5], 'big')
          DST_ADDR = socks5req[5:5+DST_ADDR_LEN].decode('ascii')
          DST_PORT = int.from_bytes(socks5req[5+DST_ADDR_LEN:5+DST_ADDR_LEN+2], 'big')
          socks5res = VER_5 + REP_SUCCEEDED + TCP_RSV + ATYP_IPV4 + socket.inet_aton(BND_ADDR) + BND_PORT.to_bytes(2, 'big')
        
        clientsock.send(socks5res)

        if CMD != CMD_UDP:
          # if DST_ADDR == '93.184.216.34':
          Thread(target=start_ws_tunnel, args=(DST_ADDR, DST_PORT, clientsock, clientaddr, )).start()

        socks5clients.remove(client)
    except Exception as e:
      print(e)
      pass

def udp_handler(interrupt):
  udpsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udpsocket.bind((SOCKS5_SERVER_IP, SOCKS5_SERVER_PORT))

  while not interrupt.is_set():
    try:
      udpreq, clientaddr = udpsocket.recvfrom(2048)
      RSV = udpreq[0:2]
      FRAG = udpreq[2:3]
      ATYP = udpreq[3:4]

      if ATYP == ATYP_IPV4:
        DST_ADDR_LEN = ATYP_IPV4_LEN
        DST_ADDR = socket.inet_ntoa(udpreq[4:4+DST_ADDR_LEN])
        offset = 4
      elif ATYP == ATYP_IPV6:
        DST_ADDR_LEN = ATYP_IPV6_LEN
        DST_ADDR = socket.inet_ntop(socket.AF_INET6, udpreq[4:4+DST_ADDR_LEN])
        offset = 4
      elif ATYP == ATYP_DNS:
        DST_ADDR_LEN = int.from_bytes(udpreq[4:5], 'big')
        DST_ADDR = udpreq[5:5+DST_ADDR_LEN].decode('ascii')
        offset = 5
      else:
        raise Exception('Invalid address type!')
      
      DST_PORT = int.from_bytes(udpreq[offset+DST_ADDR_LEN:offset+DST_ADDR_LEN+2], 'big')
      data = udpreq[offset+DST_ADDR_LEN+2:]
      udpres = udpreq[:offset+DST_ADDR_LEN+2] + (b'UDP:'+ data)
      if DST_ADDR == '104.26.6.171':
        print(clientaddr, 'UDP', (DST_ADDR, DST_PORT), data, sep=' -> ')
        udpsocket.sendto(udpres, clientaddr)
      sleep(1)
    except:
      pass

if __name__ == '__main__':
  from threading import Thread, Event

  interrupt = Event()

  client_collector_thread = Thread(target=client_collector, args=(interrupt, ))
  tcp_thread = Thread(target=tcp_handler, args=(interrupt, ))
  udp_thread = Thread(target=udp_handler, args=(interrupt, ))

  client_collector_thread.start()
  tcp_thread.start()
  udp_thread.start()

  input("Press enter to stop program...")
  interrupt.set()

  client_collector_thread.join()
  tcp_thread.join()
  udp_thread.join()