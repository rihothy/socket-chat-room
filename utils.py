from Crypto.Cipher import AES
from Crypto import Random
import struct
import json

max_buff_size = 1024
key = b'fdj27pFJ992FkHQb'

def encrypt(data):
    code = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, code)
    return code + cipher.encrypt(data)


def decrypt(data):
    return AES.new(key, AES.MODE_CFB, data[:16]).decrypt(data[16:])


def pack(data):
    return struct.pack('>H', len(data)) + data


def send(socket, data_dict):
    socket.send(pack(encrypt(json.dumps(data_dict).encode('utf-8'))))


def recv(socket):
    data = b''
    surplus = struct.unpack('>H', socket.recv(2))[0]
    socket.settimeout(5)
    while surplus:
        recv_data = socket.recv(max_buff_size if surplus > max_buff_size else surplus)
        data += recv_data
        surplus -= len(recv_data)
    socket.settimeout(None)
    return json.loads(decrypt(data))