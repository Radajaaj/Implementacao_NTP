# Esse arquivo armazena todas as função responsáveis pelas operações de criptografia do sistema

import hmac
import hashlib
import struct


# Dicionário de chaves pré-compartilhadas, usado pelo servidor na autenticação
CHAVES_DICT = {
    1: b"eu_sou_uma_chave",             # Equivale ao keyid 1
    2: b"chave_chavosa_chaveada",       # Equivale ao keyid 2
    42: b"super_chave_chavosa",         # Equivale ao keyid 42
    51: b"chave_chavente_chaveante",    # etc...
    55: b"eu_nao_sou_uma_chave"
}


def calcular_hmac(packet, keyid):
    # Função que recebe um keyid, e calcula o HMAC de um pacote com base na chave armazenada pelo servidor
    
    chave = CHAVES_DICT.get(keyid)  # Servidor pega o keyid fornecido pelo cliente, e verifica se ele é válido
    
    if not chave:
        print("Keyid inválido!")
        return 0
    
    # Depois, o servidor calcula o hmac com base na sua chave equivalente ao keyid fornecido pelo usuário
    hmac_packet = hmac.new(chave, packet, hashlib.sha256).digest()
    return hmac_packet              # E retorna o hash calculado


def calcular_hmac_client(packet, chave):
    # Função aonde um cliente envia uma chave e um pacote, e recebe um HMAC equivalente
    return hmac.new(chave, packet, hashlib.sha256).digest()
    

def validar_hmac(packet):
    # Pega um pacote recebido pelo server, e valida ele
    
    if len(packet) < 48 + 4 + 32:
        return False, 0, 0    # Pacote muito curto para ter autenticação
    
    # Separa o Key ID e o HMAC, para poder usá-los depois
    keyid = struct.unpack("!I", packet[-36:-32])[0]
    hmac_recebido = packet[-32:]
    
    # Agora o servidor vai recalcular o hmac usando apenas o keyid, e a chave que ele tem armazenada referente à esse keyid.
    packet_sem_hmac_keyid = packet[:-36]
    
    try:
        hmac_recalculado = calcular_hmac(packet_sem_hmac_keyid, keyid)  # Tenta calcular o hmac com base no keyid enviado pelo cliente
        if hmac_recalculado == 0:
            return False, 0, 0
    except ValueError:
        return False, 0, 0    # Significa que o keyid não existia/inválido
    
    # Por fim compara os dois, pra ver se o cliente enviou um pacote válido
    # Vale notar que não adianta o cliente só enviar uma chave válida. Ele precisa enviar o seu keyid válido correspondente também
    return hmac.compare_digest(hmac_recebido, hmac_recalculado), keyid, CHAVES_DICT.get(keyid)