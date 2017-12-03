import subprocess # https://docs.python.org/3/library/subprocess.html
import socket # https://docs.python.org/3/library/socket.html
from socket import socket as sock
import threading

import webserver

invalidos = "|;>" #Parametros considerados maliciosos

# Funcao para executar o comando
#   cmd = Comando a ser executado
#   arg = Argumentos desse comando
def Executar(cmd, arg):
    
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
    
def Empacotar():
    return False

def Desempacotar():
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
    source_addr = pacote[96:128]
    dest_addr = pacote[128:160]
    options[160:-1]
    
    return dest_addr, source_addr, protocol, options

# Classe para o servidor multithread
#   Referencia: goo.gl/cG7RuJ
class Servidor(object):
    def __init__(self, _host, _port):
        self.host = _host
        self.port = _port
        
        # Documentacao: https://goo.gl/T1rchX
        self.socket = sock(socket.AF_INET, socket.SOCK_STREAM) # Criacao de um novo socket
        
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
                        lista = []
                        lista = Desempacotar(pacote)
                    except ValueError:
                        print("Pacote corrompido ou fora dos padroes.")
                        conn.close()
                        return False
                    
                    resp = Executar(lista[0], lista[1])
                    pacote2 = Empacotar(lista[0], lista[2], lista[3], lista[4])
                    
                    try:                    
                        conn.send(pacote2)
                    except:
                        print("Nao foi possivel enviar a resposta")
                        
            except:
                print("Nao foi possivel receber informacoes dessa conexao")
                conn.close()
                return False