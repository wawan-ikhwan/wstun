from rfc1928_constants import *
import socket

class MethodRequest:
  '''
  +----+----------+----------+
  |VER | NMETHODS | METHODS  |
  +----+----------+----------+
  | 1  |    1     | 1 to 255 |
  +----+----------+----------+
  '''

  @staticmethod
  def from_bytes(tcpdata: bytes):
    return MethodRequest(tcpdata[0:1], tcpdata[1:2], tcpdata[2:])

  def __init__(self, VER: bytes, NMETHOD: bytes, METHODS: bytes):
    self.VER: bytes = VER
    self.NMETHOD: bytes = NMETHOD
    self.METHODS: bytes = METHODS


class MethodResponse:
  '''
  +----+--------+
  |VER | METHOD |
  +----+--------+
  | 1  |   1    |
  +----+--------+
  '''
  
  @staticmethod
  def from_req(req: MethodRequest):
    if req.VER != VER_5:
      raise Exception("Currently I don't implement socks protocol other than 5.")

    if req.NMETHOD != b'\x01':
      raise Exception("Currently I don't implement method that no other than 1 methods.")
    
    if req.METHODS != METHOD_NOAUTHENTICATIONREQUIRED:
      raise Exception("Currently I don't implement authentication method.")

    return MethodResponse(req.VER, req.METHODS)
      
  
  def __init__(self, VER: bytes, METHOD: bytes):
    self.VER: bytes = VER
    self.METHOD: bytes = METHOD

  def to_bytes(self) -> bytes:
    return self.VER + self.METHOD

class SOCKS5Request:
  '''
  +----+-----+-------+------+----------+----------+
  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
  +----+-----+-------+------+----------+----------+
  | 1  |  1  | X'00' |  1   | Variable |    2     |
  +----+-----+-------+------+----------+----------+
  '''
  
  @staticmethod
  def from_bytes(tcpdata: bytes):
    return SOCKS5Request(
      tcpdata[0:1],
      tcpdata[1:2],
      tcpdata[2:3],
      tcpdata[3:4],
      tcpdata[4:-2],
      tcpdata[-2:]
    )
  
  def __init__(self, VER: bytes, CMD: bytes, RSV: bytes, ATYP: bytes, DST_ADDR: bytes, DST_PORT: bytes):
    self.VER: bytes = VER
    self.CMD: bytes = CMD
    self.RSV: bytes = RSV
    self.ATYP: bytes = ATYP
    self.DST_ADDR: bytes = DST_ADDR
    self.DST_PORT: bytes = DST_PORT

    if self.ATYP == ATYP_IPV4:
      self.ATYP_LEN = ATYP_IPV4_LEN
    elif self.ATYP ==  ATYP_DNS:
      self.ATYP_LEN: int = self.DST_ADDR[0]
      self.DST_ADDR = self.DST_ADDR[1:]
    elif self.ATYP == ATYP_IPV6:
      raise Exception("Currently I don't implement ATYP IPV6.")
    else:
      raise Exception(f"Your ATYP doesn't conform RFC1928 which is {self.ATYP}")
  
  def get_addr(self) -> str:
    if self.ATYP == ATYP_IPV4:
      return socket.inet_ntoa(self.DST_ADDR)
    elif self.ATYP ==  ATYP_DNS:
      return self.DST_ADDR.decode('ascii')
    elif self.ATYP == ATYP_IPV6:
      raise Exception("Currently I don't implement ATYP IPV6.")
    else:
      raise Exception(f"Your ATYP doesn't conform RFC1928 which is {self.ATYP}")
  
  def get_proto(self) -> str:
    if self.CMD == CMD_BIND:
      return 'BIND'
    elif self.CMD == CMD_CONNECT:
      return 'TCP'
    elif self.CMD == CMD_UDP:
      return 'UDP'
    raise Exception(f'Unknown protocol! {self.CMD}')

class SOCKS5Response:
  '''
  +----+-----+-------+------+----------+----------+
  |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
  +----+-----+-------+------+----------+----------+
  | 1  |  1  | X'00' |  1   | Variable |    2     |
  +----+-----+-------+------+----------+----------+
  '''

  @staticmethod
  def from_req(req: SOCKS5Request):
    if req.VER != VER_5:
      raise Exception(f"Currently I don't implement socks protocol other than 5. Yours was {req.VAR}")

    if req.CMD == CMD_BIND:
      raise Exception(f"Currently I don't implement command for bind.")

    if req.RSV != TCP_RSV:
      raise Exception(f"It's weird that the RSV part is not TCP_RSV {TCP_RSV} which yours was {req.RSV}")

    if req.CMD == CMD_CONNECT:
      REP = REP_SUCCEEDED
      ATYP = ATYP_IPV4
      BND_ADDR: bytes = socket.inet_aton('192.168.43.248')
      BND_PORT: bytes = int(1080).to_bytes(2, 'big')
      return SOCKS5Response(req.VER, REP, req.RSV, ATYP, BND_ADDR, BND_PORT)
    
    REP = REP_SUCCEEDED
    ATYP = ATYP_IPV4
    BND_ADDR: bytes = socket.inet_aton('192.168.43.248')
    BND_PORT: bytes = int(1080).to_bytes(2, 'big')
    return SOCKS5Response(req.VER, REP, req.RSV, ATYP, BND_ADDR, BND_PORT)
    

  def __init__(self, VER: bytes, REP: bytes, RSV: bytes, ATYP: bytes, BND_ADDR: bytes, BND_PORT: bytes):
    self.VER: bytes = VER
    self.REP: bytes = REP
    self.RSV: bytes = RSV
    self.ATYP: bytes = ATYP
    self.BND_ADDR: bytes = BND_ADDR
    self.BND_PORT: bytes = BND_PORT

    if self.ATYP == ATYP_IPV4:
      self.ATYP_LEN = ATYP_IPV4_LEN
    elif self.ATYP ==  ATYP_DNS:
      self.ATYP_LEN: int = self.BND_ADDR[0]
      self.BND_ADDR = self.BND_ADDR[1:]
    elif self.ATYP == ATYP_IPV6:
      raise Exception("Currently I don't implement ATYP IPV6.")
    else:
      raise Exception(f"Your ATYP doesn't conform RFC1928 which is {self.ATYP}")
  
  def to_bytes(self):
    return self.VER + self.REP + self.RSV + self.ATYP + self.BND_ADDR + self.BND_PORT

class UDPRequest:
  '''
  +----+------+------+----------+----------+----------+
  |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
  +----+------+------+----------+----------+----------+
  | 2  |  1   |  1   | Variable |    2     | Variable |
  +----+------+------+----------+----------+----------+
  '''
  @staticmethod
  def from_bytes(udpdata: bytes):
    RSV: bytes = udpdata[0:2]
    FRAG: bytes = udpdata[2:3]
    ATYP: bytes = udpdata[3:4]
    offset = 0
    if ATYP == ATYP_IPV4:
      ATYP_LEN = ATYP_IPV4_LEN
    elif ATYP ==  ATYP_DNS:
      ATYP_LEN: int = udpdata[4]
      dst_addr_offset += 1
    else:
      raise Exception('IPv6 not supported yet in UDPRequest.')
    
    DST_ADDR: bytes = udpdata[offset+4: offset+4+ATYP_LEN]
    DST_PORT: bytes = udpdata[offset+4+ATYP_LEN : offset+4+ATYP_LEN+2]
    DATA: bytes = udpdata[offset+4+ATYP_LEN+2 : ]
    
    print(
      RSV,
      FRAG,
      ATYP,
      DST_ADDR,
      DST_PORT,
      DATA
    )
    
    return UDPRequest(
      RSV,
      FRAG,
      ATYP,
      DST_ADDR,
      DST_PORT,
      DATA
    )

  def __init__(self, RSV: bytes, FRAG: bytes, ATYP: bytes, DST_ADDR: bytes, DST_PORT: bytes, DATA: bytes):
    self.RSV: bytes = RSV
    self.FRAG: bytes = FRAG
    self.ATYP: bytes = ATYP
    self.DST_ADDR: bytes = DST_ADDR
    self.DST_PORT: bytes = DST_PORT
    self.DATA: bytes = DATA

  def get_addr(self) -> str:
    if self.ATYP == ATYP_IPV4 or self.ATYP == ATYP_IPV6:
      return socket.inet_ntoa(self.DST_ADDR)
    else:
      return self.DST_ADDR.decode('ascii')
  

  def info(self) -> None:
    print('RSV :', self.RSV)
    print('FRAG:', int.from_bytes(self.FRAG, 'big'))
    if self.ATYP == ATYP_IPV4:
      print('ATYP: IPv4')
    elif self.ATYP == ATYP_IPV6:
      print('ATYP: IPv6')
    elif self.ATYP == ATYP_DNS:
      print('ATYP: DNS')
    else:
      print('ATYP: Unknown')

    if self.ATYP == ATYP_IPV4 or self.ATYP == ATYP_IPV6:
      print('DST_ADDR:', socket.inet_ntoa(self.DST_ADDR))
    else:
      print('DST_ADDR:', self.DST_ADDR.decode('ascii'))
    
    print('DST_PORT:', int.from_bytes(self.DST_PORT, 'big'))
    print('DATA:', self.DATA)

  def to_bytes(self, data=b'') -> bytes:
    if self.ATYP == ATYP_IPV4 or self.ATYP == ATYP_IPV6:
      return UDP_RSV+self.FRAG+self.ATYP+self.DST_ADDR+self.DST_PORT+data
    else:
      return UDP_RSV+self.FRAG+self.ATYP+len(self.DST_ADDR).to_bytes(1, 'big')+self.DST_ADDR+self.DST_PORT+data

class Socks5Socket:

  def __init__(self, tcpsocket: socket.socket, udpsocket: socket.socket):
    client, addr = tcpsocket.accept()
    client.send(MethodResponse.from_req(MethodRequest.from_bytes(client.recv(1024))).to_bytes())
    socks5req: SOCKS5Request = SOCKS5Request.from_bytes(client.recv(1024))
    socks5res: SOCKS5Response = SOCKS5Response.from_req(socks5req)
    client.send(socks5res.to_bytes())
    if socks5req.CMD == CMD_CONNECT:
      self.client = client
      self.clientaddr = addr
    elif socks5req.CMD == CMD_UDP:
      pass
    else:
      raise Exception('CMD_BIND not implemented!')