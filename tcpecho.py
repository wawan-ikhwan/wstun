from threading import Thread
import socket

def handle_client(csock: socket.socket, caddr: tuple):
  try:
    while 1:
      data = csock.recv(4096)
      if not data:
        break
      csock.send(b'ECHO: '+data+b'\n')
  except Exception as e:
    print('Connection closed:', caddr, e)
    csock.close()
    del csock
    print(__name__, e)

def main():
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.bind(("192.168.43.248", 20000))
  sock.listen(5)

  while 1:
    csock, caddr = sock.accept()
    print(csock, caddr)
    Thread(target=handle_client, args=(csock, caddr, )).start()

if __name__ == '__main__':
  main()