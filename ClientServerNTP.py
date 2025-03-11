import socket
import random
from estruturas import *

# Lista de servidores oficiais do ntp.br, usados quando o cliente não informa um servidor a ser utilizado.
ips_oficiais = ["200.160.0.8", "200.189.40.8", "200.192.232.8"]

# Abaixo, o alguns dos parâmetros globais descritos na RFC
VERSION   = 4
REFTIME   = to_NTPtimestamp(0)

# Variáveis globais
delta     = 0
theta     = 0
root_dispersion = 0
recv_timestamp = 0
xmt_timestamp = 0


def traduzir_resposta_ntp(pacote, escrever, poll):
    #Recebe uma resposta de um servidor NTP, e mostra os principais dados na tela.
    
    global recv_timestamp, xmt_timestamp, root_dispersion
    
    if len(pacote) < 48:
        print("Pacote NTP inválido.")
        return
    
    # Convertendo timestamps de NTP_Timestamp para double
    root_delay      = ntpshort_to_double(struct.unpack("!HH", pacote[4:8]))
    root_dispersion = ntpshort_to_double(struct.unpack("!HH", pacote[8:12]))
    ref_timestamp   = timestamp_to_double(struct.unpack("!II", pacote[16:24])) - 2208988800
    orig_timestamp  = timestamp_to_double(struct.unpack("!II", pacote[24:32])) - 2208988800
    recv_timestamp  = timestamp_to_double(struct.unpack("!II", pacote[32:40])) - 2208988800
    xmt_timestamp   = timestamp_to_double(struct.unpack("!II", pacote[40:48])) - 2208988800
    
    # Desempacota o resto dos campos da resposta
    li_vn_mode, stratum, poll, precision = struct.unpack("! B B B b", pacote[:4])
    
    mode = li_vn_mode & 0b111   # Os últimos 3 bits representam o modo (4 = servidor)
    
    
    ref_id = pacote[12:16].decode('latin1')
   
    
    if stratum == 0:            # Avalia os diferentes kisses of death que o servidor pode enviar
        ref_id_str = ref_id
        if ref_id_str == 'DENY' or ref_id_str == 'RSTR':
            # Servido requer o fim da conexão com co cliente.
            print("Servidor pediu o fim da conexão! Kiss of death DENY ou RSTR.")
            exit()
        elif ref_id_str == 'RATE':
            print("Servidor pediu aumento do intervalo de polling!! Kiss of death RATE.")
            if poll > 1:
                if poll < 15:
                    poll = poll + 1
            else:
                poll = 1
            
    if escrever != 's':         # Verifica se o usuário pediu para escrever o pacote inteiro na tela
        return poll
    
    print(f"Stratum: {stratum}")
    print(f"Modo: {mode}")
    print(f"Root Delay: {root_delay}")
    print(f"Root Dispersion: {root_dispersion}")
    print(f"Reference Timestamp: {ref_timestamp}")
    print(f"Originate Timestamp: {orig_timestamp}")
    print(f"Receive Timestamp:  {recv_timestamp}")
    print(f"Transmit Timestamp: {xmt_timestamp}")
    print(f"Refid: {ref_id}")
    print("=======-==-======--======-==-=======\n")
    
    return poll


def interpretador_pacote_server(pacote, rec, escrever, keyid, chave):
    # Função aonde um servidor processa um pacote recebido, e cria um novo como resposta.
    
    global root_dispersion, REFTIME, VERSION, delta
    # Recebe uma requisição de um cliente NTP, processa ela, e prepara uma resposta
    if len(pacote) < 48:
        print("Pacote NTP inválido.")
        return
    
    
    li_vn_mode, stratum, poll, precision = struct.unpack("! B B B b", pacote[:4])
    LI = (li_vn_mode >> 6) & 0b11                       # Os 2 primeiros bits representam o LI
    mode = li_vn_mode & 0b111                           # Os 3 bits seguintes representam o mode
    
    ref_id = pacote[12:16].decode('latin1')             # Desempacotamento do resto dos elementos do header
    root_delay_pacote       = ntpshort_to_double(struct.unpack("!HH", pacote[4:8]))
    root_dispersion_pacote  = ntpshort_to_double(struct.unpack("!HH", pacote[8:12]))
    ref_timestamp_pacote    = timestamp_to_double(struct.unpack("!II", pacote[16:24]))
    orig_timestamp_pacote   = timestamp_to_double(struct.unpack("!II", pacote[24:32]))
    recv_timestamp_pacote   = timestamp_to_double(struct.unpack("!II", pacote[32:40]))
    xmt_timestamp_pacote    = timestamp_to_double(struct.unpack("!II", pacote[40:48]))
    
    if escrever == 's':                                 # Se o user quiser, será mostrado o pacote na tela.            
        print(f"Stratum: {stratum}")
        print(f"Modo: {mode}")
        print(f"Root Delay: {root_delay_pacote}")
        print(f"Root Dispersion: {root_dispersion_pacote}")
        print(f"Reference Timestamp: {ref_timestamp_pacote}")
        print(f"Originate Timestamp: {orig_timestamp_pacote}")
        print(f"Receive Timestamp:   {recv_timestamp_pacote}")
        print(f"Transmit Timestamp: {xmt_timestamp_pacote}")
        print(f"Refid: {ref_id}")
        print("=======-==-======--======-==-=======\n")
    
    
    return packet_builder(
        LI,                             # Leap Indicator (sem mudanças)
        VERSION,                        # Número da versão
        4,                              # Modo 4 (servidor)
        2,                              # Stratum 2 (servidor secundário)
        poll,                           # Poll interval do cliente
        precision,                      # Precisão do relógio docliente
        to_NTPshort(delta / 2),         # Root delay
        to_NTPshort(root_dispersion),   # Root dispersion
        0,                              # Ref ID (código de identificação do servidor)
        REFTIME,                        # Timestamp de referência
        pacote[24:32],                  # Timestamp de origem
        rec,                            # Timestamp de recebimento
        NTP_timestamp(),                # Timestamp de transmissão
        None,                           # Campos de extensão (não usados)
        None,                           # Campos de extensão (não usados)
        keyid,                          # Key ID 
        chave                           # Message digest  
    )


def requisicao_NTP(server, poll, ajustar, escrever, keyid, chave):
    # Função que um cliente chama quando quer criar um socket para enviar e receber pacotes NTP
    
    global REFTIME                          # Var global, última vez que o clock foi atualizado.
    global delta, theta                     # Vars globais de offset e round-trip delay
    
    # Criação de um socket UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Gera o pacote NTP e envia para o servidor
    pacote = packet_builder( 00, VERSION, 3, 0, poll, calcPrecision(), to_NTPshort(0), to_NTPshort(0), 0, REFTIME, NTP_timestamp(), to_NTPtimestamp(0), to_NTPtimestamp(0), None, None, keyid, chave)

    T1 = time.time()                        # Tempo de envio do pacote

    try:
        sock.sendto(pacote, server)         # Envia o pacote ao servidor
        sock.settimeout(5)                  # 5 segundos de timeout
        
        resposta, ip = sock.recvfrom(1024)  # Espera a resposta
        T4 = time.time()                    # Tempo de recebimento do pacote

    except TimeoutError:                    # Ativa em caso de timeout
        print("Timeout! Nenhuma resposta do servidor.")
        return poll
    
    sock.close()                            # Fecha o socket

    poll = traduzir_resposta_ntp(resposta, escrever, poll)   # Extrai os valores de timestamp da resposta, e mostra o pacote na tela se o usuário desejar

    # Offset de B relativo a A:     theta = T(B) - T(A) = 1/2 * [(T2-T1) + (T3-T4)]
    theta = (1/2) * ((recv_timestamp - T1) + (xmt_timestamp - T4))
    # Round trip delay entre A, B, e A: delta = T(ABA) = (T4-T1) - (T3-T2)
    delta = (T4 - T1) - (xmt_timestamp - recv_timestamp)

    print(f"O Offset é de           {theta} segundos")
    print(f"O Round-Trip Delay é de {delta} segundos")

    server_time = T4 + theta                # Calcula o horário certo corrigido segundo

    # agora, corrigimos o relógio do próprio sistema.
    if ajustar == 's':
        ajustar_relogio(server_time)
        print("Horário do sistema ajustado!")
    
    print("\n...\n")
    
    return poll


def modo_client(server):    
    # Funções referentes às requisições NTP feitas pelo modo de associação 3 (client)
    
    # Primeiro, vemos se o usuário deseja utilizar uma chave previamente compartilhada
    chave  = input("\nInsira a chave compartilhada (Se não for usar uma, responda '0')\nr: ").encode()
    keyid  = int(input("\nInsira o Key_id (Se não for usar um, responda '0')\nr: "))
       
    # Pergunta ao usuário se o client vai ficar atualizando o relógio em loop (polling)
    poll = input("\nUsar polling? [s/n]\nR: ")

    if poll == 's':
        poll = int(input("\nQual o valor de poll? (sugere-se entre 6 e 10)\n- Alguns servidores não aceitam requisições com um polling muito baixo.\nR: "))
    else:
        poll = 0

    # Caso o usuário quiser, o sistema irá atualizar o relógio do SO de acordo com a resposta do servidor
    ajustar  = input("\nDeseja tentar atualizar o horário do sistema com base na(s) resposta(s)? [s/n]\nR: ")
    
    # Para caso o usuário deseje ver todas as informações dos pacotes NTP recebidos. 
    # Caso negativo, o sistema só vai mostrar o offset, o round-trip delay, e o horário correto na tela.
    escrever = input("\nDeseja mostrar na tela todos os conteúdos do(s) pacotes(s) recebido(s)? [s/n] \nR: ")

    if poll == 0:
        # Se não tiver polling, o envio do pacote oorrerá uma única vez.
        print("\n=====-==-=== Pacote NTP ===-==-=====")
        poll = requisicao_NTP(server, poll, ajustar, escrever, keyid, chave)      # Faz uma única requisição
        return
    else:
        while True:
            # Se tiver polling, o envio do pacote oorrerá infinitamente.
            print("\n=====-==-=== Pacote NTP ===-==-=====")
            poll = requisicao_NTP(server, poll, ajustar, escrever, keyid, chave)
            time.sleep(2 ** poll)    # Faz várias requisções seguindo o intervalo escolhido
    
    return


def modo_server(server):
    # Funções referentes às requisições NTP feitas pelo modo de associação 4 (server)
    
    # Para caso o usuário deseje ver todas as informações dos pacotes NTP recebidos. 
    # Caso negativo, o sistema só vai mostrar que um pacote foi recebido.
    escrever   = input("\nDeseja mostrar na tela todos os conteúdos do(s) pacotes(s) recebido(s)? [s/n] \nR: ")
    
    # Vemos se o usuário deseja utilizar uma chave previamente compartilhada para validar os pacotes recebidos
    autenticar = input("\nDeseja usar autenticação por HMAC-SHA256? [s/n]\nr: ")
    
    # Criação de um socket UDP, que é anexado ao IP do servidor
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(server)
    
    print(f"\nServidor iniciado em {server[0]}:{server[1]}, aguardando requisições...")
    
    # Recebe dados dos clientes de forma constante:
    while True:
        data, address = sock.recvfrom(1024)
        rec = NTP_timestamp()                               # Calcula o receive timestamp.
  
        if address != 0:
            
            if autenticar == 's':                           # Caso a autenticação estiver ativada..
                validade, keyid, chave = validar_hmac(data) # Verifica se o pacote é válido
                
                if validade:
                    print("\nPacote autêntico recebido")
                else:
                    print("\nPacote falso recebido!")
                    continue                                # Descarta o pacote
            else:
                keyid, chave = 0, 0
            
            print("\n=====-==-=== Pacote NTP ===-==-=====")
            print(f"Pacote recebido de {address}:")
            data = interpretador_pacote_server(data, rec, escrever, keyid, chave)
            
            sock.sendto(data, address)                      # Envia o pacote ao servidor
            print(f"Resposta enviada para {address}:")

    return


if __name__ == "__main__":
    while(True):
        # Pergunta se o programa será executado no modo cliente ou servidor (outros modos de associação não são suportados)
        modo = input("\nEscolha um modo de associação: [3 - client] [4 - servidor]\n - Antes de iniciar um servidor, recomenda-se sincronizar com um servidor oficial pelo modo client.\nR: ")
        
        # Pedindo ao usuário o IP do servido 
        server_ip   = input("\nInsira o endereço do servidor, ou '0' para usar um aleatório\nR: ")
        server_port = int(input("\nInsira a porta. Recomendado: 123\nR: "))

        # Valida o IP. Se for inválido, só usa um dos servidores oficiais
        if server_ip == "0":
            server_ip = random.choices(ips_oficiais)[0]
            print("\nIP selecionado: ", server_ip)

        server = (server_ip, server_port)
        
        

        if modo == "3":
            modo_client(server)     # Executa o client NTP
        elif modo == "4":
            modo_server(server)     # Executa o servidor NTP
        else:
            print("\nErro! Modo de associação ainda não suportado.")