# Esse arquivo armazena todas as função responsáveis por operações feitas em cima dos tipos de dados próprios do NTP
# Também armazena a função responsável por mudar o horário do sistema operacional

import time
import math
import sys
import datetime
import subprocess
from crypto import *

REFTIME = 0
CHAVE   = 0
KEY_ID  = 1

def to_NTPtimestamp(tempo):
    # Converte um valor de tempo (em segundos) em ponto flutuante para o formato NTP Timestamp
    # Primeiros 32 bits - inteiro       Ultimos 32 bits - fracionário
    
    inteiro = int(tempo)                                # Recebe a parte inteira do tempo
    fracionario = int((tempo - inteiro) * (2**32))      # Separa a parte fracionária

    return struct.pack("!II", inteiro, fracionario)     # Retorna num formato binário


def timestamp_to_double(timestamp):
    # Converte um timestamp NTP de 64 bits (seconds, fraction) para um valor de ponto flutuante (double).
    # Primeiros 32 bits - inteiro       Ultimos 32 bits - fracionário
    
    seconds, fraction = timestamp                       # Separa a parte inteira da fracionária
    return seconds + (fraction / 2**32)                 # Converte fração para segundos e soma


def ntpshort_to_double(ntpshort):
    # Converte um valor de tempo (em segundos) em ponto flutuante para o formato NTP Short
    # Primeiros 16 bits - inteiro       Ultimos 16 bits - fracionário
    
    seconds, fraction = ntpshort                        # Separa a parte inteira da fracionária
    return seconds + (fraction / 2**16)                 # Converte fração para segundos e soma


def to_NTPshort(tempo):
    # Converte um valor de tempo (em segundos) em ponto flutuante para o formato NTP Short
    # Primeiros 16 bits - inteiro       Ultimos 16 bits - fracionário
    
    inteiro = int(tempo)                                # Recebe a parte inteira do tempo
    fracionario = int((tempo - inteiro) * (2**16))      # Separa a parte fracionária
    
    # Representação para valores negativos (complemento de dois)
    inteiro = inteiro & 0xFFFF
    fracionario = fracionario & 0xFFFF
    
    return struct.pack("!HH", inteiro, fracionario)     # Retorna num formato binário


def NTP_timestamp():
    # Retorna o intante atual no formato NTP Timestamp
    # Primeiros 32 bits - inteiro       Ultimos 32 bits - fracionário

    diferenca_ntp = 2208988800                          # Time.time() tem seu retorno no formato UNIX epoch, que começa em 1970
    timestamp = time.time() + diferenca_ntp             # Adicionamos 70 anos para converter ao formato NTP epoch, que começa em 1900
    
    inteiro = int(timestamp)                            # Convertemos para o formato NTP_timestamp, que separa aparte inteira da fracionária
    fracionario = int((timestamp - inteiro) * (2**32))  
    
    return struct.pack("!II", inteiro, fracionario)     # Retorna um packet binário


def calcPrecision():
    # Calcula a precisão do relógio do sistema usando a biblioteca time.
    start_time = time.perf_counter()
    end_time   = time.perf_counter()
    
    # Basicamente faz duas consultas de tempo consecutivas, para definir o intervalo de tempo mínimo que o sistema consegue identificar
    precision_seconds = end_time - start_time           
    
    return int(math.log2(precision_seconds) if precision_seconds > 0 else None)


def packet_builder( 
    # Recebe todas as variáveis necessárias para a criação de um pacote NTP, e retorna um pacote binário pronto para ser enviado
    
        LI,                             # Leap Indicator,       2 bits
        VN,                             # Version Number        3 bits
        mode,                           # mode                  3 bits      3 - client, 4 - server.
        stratum,                        # stratum               8 bits      não usado pelo client
        poll,                           # poll exponent         8 bits      frequência de envio de mensagens. 0 = uma só mensagem
        precision,                      # precision exponent    8 bits
        rootdelay,                      # root delay            32 bits, NTP short  
        rootdisp,                       # root dispersion       32 bits, NTP short
        refid,                          # reference ID          32 bits
        reftime,                        # reference timestamp   64 bits, NTP timestamp
        org,                            # origin timestamp      64 bits, NTP timestamp
        rec,                            # receive timestamp     64 bits, NTP timestamp
        xmt,                            # transmit timestamp    64 bits, NTP timestamp
        exf1,                           # Extension Field 1     variável
        exf2,                           # Extension Field 2     variável
        keyid,                          # key ID                32 bits
        chave                           # message digest        128 bits MD5 hash
    ):

    # Agora montamos o cabeçalho
    packet = struct.pack(               # Convertemos para binário os parâmetros que não vieram nesse formato
        "! B B B b",
        (LI << 6) | (VN << 3) | mode,   # LI, VN, mode  (1 byte)
        stratum,                        # stratum       (1 byte)
        poll,                           # poll          (1 byte)
        precision                       # precision     (1 byte)
    ) + rootdelay + rootdisp            # 4 bytes e 4 bytes
    
    packet += struct.pack(              # Convertemos para binário os parâmetros que não vieram nesse formato
        "! I",
        refid                           # refid         (4 bytes)
    ) + reftime + org + rec + xmt       # reftime       (8 bytes)
    
    ## Adiciona Extension Field 1, se existir
    #if exf1:
    #    exf1_padded = exf1 + b"\x00" * ((4 - len(exf1) % 4) % 4)  # Padding para múltiplo de 4 bytes
    #    packet += exf1_padded

    ## Adiciona Extension Field 2, se existir
    #if exf2:
    #    exf2_padded = exf2 + b"\x00" * ((4 - len(exf2) % 4) % 4)  # Padding para múltiplo de 4 bytes
    #    packet += exf2_padded
    
    if keyid and chave:
        # Se existirem, calcula o digest (hash HMAC-SHA256) sobre o pacote (mas não sobre o keyid e o digest em si, conforme a RFC)
        digest = calcular_hmac_client(packet, chave)
        packet += struct.pack("!I", keyid)  # Converte o keyid para binário
        packet += digest                    # Concatena o digest no final do pacote
        
    return packet    


def ajustar_relogio(unix_time):
    # A justa o relógio do sistema com base na unidade de tempo absoluta recebida como parâmetro.
    # Suporta windows e linux
    
    global REFTIME                                                  # Armazena o último momento que o clock do sistema foi atualizado
    REFTIME = NTP_timestamp()

    # Se a plataforma for windows
    if sys.platform == 'win32':                                     # Identifica se está sendo executado no windows
        unix_time = datetime.datetime.fromtimestamp(unix_time)      # Converte UTC para a timezone local

        formatted_time = unix_time.strftime('%Y-%m-%d %H:%M:%S')    # Muda o formato para algo que o windows aceite
        subprocess.run(["powershell", f"Set-Date -Date '{formatted_time}'"], shell=True)    # Roda esse comando shell que define o horário novo
        return

    # Se não for windows, vai tentar fazer os ajustes para linux
    if sys.platform == 'linux':
        local_time = datetime.datetime.fromtimestamp(unix_time)     # Converte UTC para a timezone local
        formatted_time = local_time.strftime('%Y-%m-%d %H:%M:%S')   # Muda o formato para algo que o linux aceite
        os.system(f"sudo date -s '{formatted_time}'")               # Roda esse comando de terminal que deefine horário novo
        return
    
    # Se o programa não identificar o SO usado...
    print("Erro! Sistema Operacional não suportado.")
    return