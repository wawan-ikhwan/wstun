# pylint: disable=missing-docstring
import socket
from rfc1928_constants import *
from socks5_structure import *
from socks5_structure import SOCKS5Request, SOCKS5Response
TCP_SERVER_IP = '192.168.43.248'
TCP_SERVER_PORT = 1080

UDP_SERVER_IP = '192.168.43.248'
UDP_SERVER_PORT = 1080

tcpsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcpsocket.bind((TCP_SERVER_IP, TCP_SERVER_PORT))
tcpsocket.listen(5)

udpsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udpsocket.bind((UDP_SERVER_IP, UDP_SERVER_PORT))

def main():
  while 1:
    try:
      # Get TCP data from client
      client, addr = tcpsocket.accept()
      client.send(MethodResponse.from_req(MethodRequest.from_bytes(client.recv(1024))).to_bytes())
      socks5req: SOCKS5Request = SOCKS5Request.from_bytes(client.recv(1024))
      socks5res: SOCKS5Response = SOCKS5Response.from_req(socks5req)
      client.send(socks5res.to_bytes())
      if socks5req.CMD == CMD_CONNECT:
        actual_data: bytes = client.recv(1024)
        if socks5req.get_addr() == '27.112.79.120':
          print(addr, '->', socks5req.get_proto(), '->', (socks5req.get_addr(), int.from_bytes(socks5req.DST_PORT, 'big')), '->', actual_data)
          client.send(b'awikwok\n')
          print(client.recv(1024))
          client.send(b'amnjinc\n')
      elif socks5req.CMD == CMD_UDP:
        actual_data, clnt_addr = udpsocket.recvfrom(1024)
        print(clnt_addr)
        udpreq = UDPRequest.from_bytes(actual_data)
        udpreq.info()
        if udpreq.get_addr() == '27.112.79.120':
          print(clnt_addr, '->', socks5req.get_proto(), '->', (udpreq.get_addr(), int.from_bytes(udpreq.DST_PORT, 'big')), '->', udpreq.DATA)
          udpsocket.sendto(udpreq.to_bytes(b'pertamax\n'), clnt_addr)
          print(udpsocket.recvfrom(1024))
          udpsocket.sendto(udpreq.to_bytes(b'amnjinc kocak UDP\n'), clnt_addr) 
          print('sent')

      client.close()
      del client
    except Exception as e:
      print(e)

  # Close the TCP connection
  client.close()
  # udpclient.close()
  tcpsocket.close()


if __name__ == '__main__':
  main()
