# ALL RFC1928 CONSTANT

# VERSION_PROTOCOL
VER_5 = b'\x05'

# METHOD CONSTANT
METHOD_NOAUTHENTICATIONREQUIRED = b'\x00'
METHOD_GSSAPI = b'\x01'
METHOD_UNAMEPASSW = b'\x02'
METHOD_IANAASSIGNED: list[bytes] = [i.to_bytes(1, 'big') for i in range(int.from_bytes(b'\x03', 'big'), int.from_bytes(b'\x7f', 'big')+1)]
METHOD_RESERVED: list[bytes] = [i.to_bytes(1, 'big') for i in range(int.from_bytes(b'\x80', 'big'), int.from_bytes(b'\xfe', 'big')+1)]
METHOD_NOACCEPTABLE = b'ff'

# ATYP CONSTANT
ATYP_IPV4 = b'\x01'
ATYP_DNS = b'\x03'
ATYP_IPV6 = b'\x04'

# ATYP LENGTH
ATYP_IPV4_LEN = 4
ATYP_IPV6_LEN = 16

# CMD CONSTANT
CMD_CONNECT = b'\x01'
CMD_BIND = b'\x02'
CMD_UDP = b'\x03'

# REP CONSTANT
REP_SUCCEEDED = b'\x00'
REP_GENERALFAILURE = b'\x01'
REP_NOTALLOWED = b'\x02'
REP_NETWORKUNREACHABLE = b'\x03'
REP_HOSTUNREACHABLE = b'\x04'
REP_CONNECTIONREFUSED = b'\x05'
REP_TTLEXPIRED = b'\x06'
REP_CMDNOTSUPPORTED = b'\x07'
REP_ADDRTYPNOTSUPPORTED = b'\x08'
REP_UNASSIGNED: list[bytes] = [i.to_bytes(1, 'big') for i in range(int.from_bytes(b'\x09', 'big'), int.from_bytes(b'\xff', 'big')+1)]

# RSV CONSTANT
TCP_RSV = b'\x00'
UDP_RSV = b'\x00\x00'
