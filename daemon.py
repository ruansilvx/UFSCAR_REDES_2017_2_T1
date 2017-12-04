import subprocess # https://docs.python.org/3/library/subprocess.html
import socket # https://docs.python.org/3/library/socket.html
import threading

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

# Funcao para executar o comando
#   cmd = Comando a ser executado
#   arg = Argumentos desse comando
def Executa(cmd, arg):
    invalidos = "|;>" #Parametros considerados maliciosos
    
    # Tratamento de parametros maliciosos
    parInvalidos = []
    for c in args:
        if c in invalidos:
            parInvalidos.append(c)
    if len(parInvalidos) == 1:
        return "Parametro " + str(parInvalidos[0]) + "malicioso! O comando não sera executado."
    elif len(parInvalidos) > 1:
        return "Parametros " + ", ".join(parInvalidos) + " maliciosos! O comando não sera executado."
    
    # Execucao do comando
    try:
        print("Executando comando " + ' '.join((cmd, arg)))
        
        # Documentacao: https://goo.gl/FwzmkL
        r = subprocess.run(' '.join((cmd, arg)), check = True, stdout = PIPE, shell = true).stdout
        return r
    
    # Comando invalido
    # Documentacao: https://goo.gl/1NEnFa
    except subprocess.CalledProcessError:
        return "Comando invalido."
    
def Converte(s):
    comandos = {'00000001':'ps', '00000010':'df', '00000011':'finger', '00000100':'uptime'}
    if s in comandos:
        return comandos[s]
    return None

# Desempacota um pacote e retorna os campos utilizados pelo Daemon para executar o comando
def Desempacota(pacote):
    if len(pacote) < 160:
        return None
    
    version = pacote[:4]
    ihl = pacote[4:8]
    type_serv = pacote[8:16]
    t_length = pacote[16:32]
    ident = pacote[32:48]
    flags = pacote[48:51]
    frag_off = pacote[51:64]
    ttl = pacote[64:72]
    protocol = pacote[72:80]
    checksum = pacote[80:96]
    
    # Verificacao do checksum, ignorando o campo checksum
    if checksum != crc16(pacote[:80] + '0000000000000000' + pacote[96:]):
        print("Checksum incorreto")
        return None
    
    source_addr = pacote[96:128]
    source = socket.inet_aton(struct.pack('!I', int(source_addr.lstrip('0'), 2)))
    
    dest_addr = pacote[128:160]
    dest = socket.inet_aton(struct.pack('!I', int(dest_addr.lstrip('0'), 2)))
    
    options[160:-1]
    
    cmd = Converte(protocol)
    arg = "".join(chr(int("".join(map(str, options[i:i+8])),2)) for i in range(0,len(options),8))
    
    return dest, source, cmd, arg, ttl

# Cria um pacote a partir dos parametros e o retorna
def Empacota(cmd, arg, _dest_addr, _source_sddr, _ttl):
    version = '0010'
    ihl = '0101'
    type_serv = '00000000' 
    ident = '0000000000000001'
    flags = '111'
    frag_off = '0000000000000'
    ttl = bin(int(ttl, 2) - 1).replace("0b","")
    checksum = '0000000000000000' 
    protocol = comparabinario(comando[0])
    options  = ''.join('{0:08b}'.format(ord(x), 'b') for x in arg)[2:]
    
    source_addr = bin(struct.unpack('!I', socket.inet_aton(_source_addr))[0])[2:].zfill(32)
    dest_addr = bin(struct.unpack('!I', socket.inet_aton(_dest_addr))[0])[2:].zfill(32)
    
    t_length = bin((32 * 5) + len(options))[2:].zfill(16)
    
    pacote = ''.join( [version + ihl + type_serv + t_length + ident + flags + frag_off + ttl + protocol + checksum + source_addr + dest_addr + options])
      
    checksum = crc16(pacote.encode())

    pacote = ''.join( [version + ihl + type_serv + t_length + ident + flags + frag_off + ttl + protocol + checksum + source_addr + dest_addr + options])
    
    return pacote    
    
# Classe para o servidor multithread
#   Referencia: goo.gl/cG7RuJ
class Daemon(object):
    def __init__(self, _host, _port):
        self.host = _host
        self.port = _port
        
        # Documentacao: https://goo.gl/T1rchX
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Criacao de um novo socket
        
        self.socket.bind((host, port)) # Criacao de uma ligacao entre o socket e o endereco host:port
        self.socket.setdefaulttimeout(10) # Se uma instrucao nao terminar em 5 segundos, ela vai falhar
        
    def listen(self):
        self.socket.listen(3) # Teremos no máximo 3 daemons rodando
        
        while True:
            try:
                conn, addr = self.socket.accept()
                
                # Documentacao: https://goo.gl/UDtAWQ
                threading.Thread(group = None, target = self.listenClient, args = (conn, addr)).start()
                
            except InterruptedError:
                print("Chamada de sistema interrompida. Tente novamente!")
                
    def listenClient(self, conn, addr):
        while True:
            try:
                # Documentacao: https://goo.gl/Wb2Wtr
                pacote = conn.recv(1024) # O tamanho do buffer deve ser, preferencialmente, uma potencia de 2
                if pacote:
                    try:
                        dest_addr, source_addr, cmd, arg, ttl = Desempacota(pacote)
                    except ValueError:
                        print("Pacote corrompido ou fora dos padroes.")
                        conn.close()
                        return False
                    
                    resp = Executa(cmd, arg)
                    pacote2 = Empacota(cmd, arg, source_addr, dest_addr, ttl)
                    
                    try:                    
                        conn.send(pacote2)
                    except:
                        print("Nao foi possivel enviar a resposta")
                        
            except:
                print("Fim da conexao")
                conn.close()
                return False