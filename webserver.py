#!/usr/bin/env python
# -*- coding: utf-8 -*-
import cgitb, cgi
import socket
import struct
import binascii
import daemon


print("Content-Type: text/html;charset=utf-8\n")
# End of headers
print("<h1> Test </h1>")


cgitb.enable()

form = cgi.FieldStorage()
maqs = ['maq1', 'maq2', 'maq3']
pocom = ['ps', 'df', 'finger', 'uptime']

# Webserver 

# Cria um dicionario e adiciona todos os comandos selecionados, 
# com seus parametros, a listas indexadas pelo nomes das maquinas
from collections import defaultdict
comandos = defaultdict(list)
for maq in maqs:
    for com in pocom:
        coms = form.getlist(maq + "_" + com)
        params = form.getvalue(maq + "-" + com)
        if coms and params:
            comandos[maq].append([form.getvalue(maq + "_" + com)] + [params])
        elif coms:
            comandos[maq].append([form.getvalue(maq + "_" + com)] + [])

# Backend


# Retirado de: https://gist.github.com/oysstu/68072c44c02879a2abf94ef350d1c7c6
def crc16(data):
    data = bytearray(data)
    poly = 0x8408
    crc = 0xFFFF
    for b in data:
        cur_byte = 0xFF & b
        for _ in range(0, 8):
            if (crc & 0x0001) ^ (cur_byte & 0x0001):
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1

            cur_byte >>= 1

    crc = (~crc & 0xFFFF)
    crc = (crc << 8) | ((crc >> 8) & 0xFF)
    crc = 0x0000FFFF & crc
    return bin(crc)[2:].zfill(16)

def comparabinario(com):
    comandos = {
                 'ps': '00000001',
                 'df': '00000010',
                 'finger': '00000011',
                 'uptime': '00000100'
               }
    return comandos[com]

def empacotar(comando, end_local, end_dest):
    version = '0010'
    ihl = '0101'
    type_serv = '00000000' 
    ident = '0000000000000001'
    flags = '000'
    frag_off = '0000000000000'
    ttl = '00000010'
    checksum = '0000000000000000' 
    protocol = comparabinario(comando[0])
    options  = ''.join('{0:08b}'.format(ord(x), 'b') for x in comando[1])[2:]
    source_addr = bin(struct.unpack('!I', socket.inet_aton(end_local))[0])[2:].zfill(32)
    dest_addr = bin(struct.unpack('!I', socket.inet_aton(end_dest))[0])[2:].zfill(32)

    t_length = bin((32 * 5) + len(options))[2:].zfill(16)
        
    pacote = ''.join( [version + ihl + type_serv + t_length + ident + flags + frag_off + ttl + protocol + checksum + source_addr + dest_addr + options])
  
    checksum = crc16(pacote.encode())

    pacote = ''.join( [version + ihl + type_serv + t_length + ident + flags + frag_off + ttl + protocol + checksum + source_addr + dest_addr + options])
    
    return pacote

# Recupera a resposta do pacote vindo do daemon
def desempacotar(pacote): 
    t_length = int(pacote[16:32], 2)
    checksum = pacote
    options = list(pacote[160:t_length+1].zfill(32))
    return "".join(chr(int("".join(map(str, options[i:i+8])),2)) for i in range(0,len(options),8)).lstrip('\x00')

# Checa o campo checksum por possíveis inversões de bit
def checksum_valido(pacote):
    cksum_p = pacote[80:96]
    pac_teste = pacote[:79] + '0000000000000000' + pacote[97:]
    cksum_t = crc16(pac_teste.encode())
    if cksum_p == cksum_t:
        return True
    return False
  
# Envia os comandos para os daemons por meio de sockets
def enviar_comando(comando):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip = socket.gethostbyname(socket.gethostname())
    pacote = empacotar(comando, ip, sock.getsockname()[0])
    sock.send(pacote)
    reposta = ''
    while 1:
        pacote_resp = sock.recv(1024)
        if not pacote_resp:
            break
        else:
            if checksum_valido(pacote_resp):
                resposta += desempacotar(pacote_resp)
            else:
                return 'erro_checksum'
            
    return resposta

daemon.Daemon('localhost',8011).listen()
daemon.Daemon('localhost',8012).listen()
daemon.Daemon('localhost',8013).listen()

# Processa os comandos coletados e cria um dicionario com as 
# respostas de cada um
respostas = {}
for maq, coms in comandos.items():
    respostas[maq] = {}
    for com in coms:
        respostas[maq][com[0]] = enviar_comando(com)
        if respostas[maq][com[0]] == 'erro_checksum':
            for i in range(3):
                respostas[maq][com[0]] = enviar_comando(com)
                if respostas[maq][com[0]] != 'erro_checksum':
                    break


# Fim backend
print(respostas)
# Apresentacao dos resultados