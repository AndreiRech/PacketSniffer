from datetime import datetime
import socket
import struct
import sys
import os

# -- Constantes --
INTERFACE = "tun0"
DEBUG = False

# -- Constantes de Log --
LOG_DIR = "Logs"
INTERNET_LOG_FILE = os.path.join(LOG_DIR, "camada_internet.csv")
TRANSPORT_LOG_FILE = os.path.join(LOG_DIR, "camada_transporte.csv")
APP_LOG_FILE = os.path.join(LOG_DIR, "camada_aplicacao.csv")

INTERNET_HEADER = "Data/Hora,Protocolo,IP Origem,IP Destino,Protocolo ID,Outras Informações,Tamanho\n"
TRANSPORT_HEADER = "Data/Hora,Protocolo,IP Origem,Porta Origem,IP Destino,Porta Destino,Tamanho\n"
APP_HEADER = "Data/Hora,Protocolo,Informações\n"

# -- Quantidades de Pacotes --
IPV4_COUNT = 0
IPV6_COUNT = 0
ICMP_COUNT = 0
OTHER_IP_COUNT = 0

TCP_COUNT = 0
UDP_COUNT = 0
OTHER_TRANSPORT_COUNT = 0

HTTP_COUNT = 0
DNS_COUNT = 0
DHCP_COUNT = 0
NTP_COUNT = 0
OTHER_APP_COUNT = 0

# -- Funções Auxiliares --

def clean_terminal():
    print("\033c", end="")

def format_mac(raw_mac):
    return ':'.join(format(b, '02x') for b in raw_mac)

# ---- Funções do Log --

def create_network_log(ip_data, transport_data):
    dt_string = ip_data['date'].strftime("%Y-%m-%d %H:%M:%S")
    
    outras_infos = "-"
    protocolo_id = ip_data['protocol']
    
    if transport_data and transport_data['name'] in ["ICMP", "ICMPv6"]:
        protocolo_nome = transport_data['name']
        outras_infos = transport_data.get("info_str", "-")
    else:
        protocolo_nome = ip_data['name']

    tamanho = ip_data['total_length']
    
    return f"{dt_string},{protocolo_nome},{ip_data['src']},{ip_data['dest']},{protocolo_id},{outras_infos},{tamanho}\n"

def create_transport_log(ip_data, transport_data):
    dt_string = ip_data['date'].strftime("%Y-%m-%d %H:%M:%S")
    protocolo = transport_data['name']
    
    tamanho = ip_data['total_length']
    
    return f"{dt_string},{protocolo},{ip_data['src']},{transport_data['src_port']},{ip_data['dest']},{transport_data['dest_port']},{tamanho}\n"

def create_application_log(ip_data, application_data):
    dt_string = ip_data['date'].strftime("%Y-%m-%d %H:%M:%S")
    protocolo = application_data['name']
    
    info_str = ""
    
    if protocolo == "HTTP":
        info_str = application_data.get("request_line", "")
    elif protocolo == "DNS":
        info_str = f"ID: {application_data.get('transaction_id')} Qs: {application_data.get('questions')} Ans: {application_data.get('answers')}"
    elif protocolo == "DHCP":
        op = "Request" if application_data.get("opcode") == 1 else "Reply"
        info_str = f"Op: {op} TransID: {application_data.get('transaction_id')}"
    elif protocolo == "NTP":
        info_str = f"Ver: {application_data.get('version')} Stratum: {application_data.get('stratum')}"
    else:
        info_str = "Dados não decodificados"
        
    info_str = info_str.replace("\r", "").replace("\n", " ")
    
    return f"{dt_string},{protocolo},{info_str}\n"

def save_logs(ip_data, transport_data, application_data):
    try:
        # Crie uma pasta chamadas Logs se não existir
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR)
            if DEBUG:
                print(f"[Log] Criando diretório: {LOG_DIR}")
        
        # --- Log da Camada de Internet ---
        if ip_data:
            if not os.path.exists(INTERNET_LOG_FILE):
                with open(INTERNET_LOG_FILE, 'w') as f:
                    f.write(INTERNET_HEADER)
            
            log_string = create_network_log(ip_data, transport_data)
            if log_string:
                with open(INTERNET_LOG_FILE, 'a') as f:
                    f.write(log_string)

        # --- Log da Camada de Transporte ---
        if transport_data and transport_data['name'] not in ["ICMP", "ICMPv6"]:
            if not os.path.exists(TRANSPORT_LOG_FILE):
                with open(TRANSPORT_LOG_FILE, 'w') as f:
                    f.write(TRANSPORT_HEADER)
            
            log_string = create_transport_log(ip_data, transport_data)
            if log_string:
                with open(TRANSPORT_LOG_FILE, 'a') as f:
                    f.write(log_string)
                    
        # --- Log da Camada de Aplicação ---
        if application_data:
            if not os.path.exists(APP_LOG_FILE):
                with open(APP_LOG_FILE, 'w') as f:
                    f.write(APP_HEADER)
            
            log_string = create_application_log(ip_data, application_data)
            if log_string:
                with open(APP_LOG_FILE, 'a') as f:
                    f.write(log_string)
                    
    except PermissionError:
        print("[Erro de Log] Sem permissão para escrever no diretório 'Logs'.")
    except Exception as e:
        print(f"[Erro de Log] Falha ao salvar log: {e}")

# ---- Função do Monito --

def monitor_interface():
    print("===========================================================================================")
    print("  MONITOR DE TRÁFEGO DE REDE")
    print("===========================================================================================")
    print(f"  Interface: {INTERFACE}")
    print("  Pressione Ctrl+C para encerrar o monitoramento.")
    print("===========================================================================================")
    print("\nCAMADA DE INTERNET")
    print("-------------------------------------------------------------------------------------------")
    print(f"   IPv4: {IPV4_COUNT}")
    print(f"   IPv6: {IPV6_COUNT}")
    print(f"   ICMP: {ICMP_COUNT}")
    print(f"   Outros: {OTHER_IP_COUNT}")
    print("\nCAMADA DE TRANSPORTE")
    print("-------------------------------------------------------------------------------------------")
    print(f"   TCP: {TCP_COUNT}")
    print(f"   UDP: {UDP_COUNT}")
    print(f"   Outros: {OTHER_TRANSPORT_COUNT}")
    print("\nCAMADA DE APLICAÇÃO")
    print("-------------------------------------------------------------------------------------------")
    print(f"   HTTP: {HTTP_COUNT}")
    print(f"   DNS: {DNS_COUNT}")
    print(f"   DHCP: {DHCP_COUNT}")
    print(f"   NTP: {NTP_COUNT}")
    print(f"   Outros: {OTHER_APP_COUNT}")
    print("\n===========================================================================================")
    print(f"  TOTAL: {IPV4_COUNT + IPV6_COUNT + ICMP_COUNT + TCP_COUNT + UDP_COUNT + HTTP_COUNT + DNS_COUNT + DHCP_COUNT + NTP_COUNT + OTHER_IP_COUNT + OTHER_TRANSPORT_COUNT + OTHER_APP_COUNT} pacotes capturados")
    print("===========================================================================================")
    
    clean_terminal()

# -- Funções de Desempacotamento --

# ---- Camdada de Enlace --

def unpack_ethernet(packet):
    dest_mac_raw = packet[0:6]
    src_mac_raw = packet[6:12]
    ether_type_raw = packet[12:14]

    dest_mac = format_mac(dest_mac_raw)
    src_mac = format_mac(src_mac_raw)
    ether_type = "0x" + ''.join(format(b, '02x') for b in ether_type_raw)

    if DEBUG:
        print("\nPacote Ethernet")
        print(" - Mac de Destino:", dest_mac)
        print(" - Mac de Origem:", src_mac)
        print(" - Tipo de Protocolo:", ether_type)

    return {
        "src": src_mac,
        "dest": dest_mac,
        "ether_type": ether_type
    }

# ---- Camdada de Rede --

def unpack_ipv4(packet):
    unpacked_data = struct.unpack('!BBHHHBBH4s4s', packet[0:20])

    first_byte = unpacked_data[0]
    version = first_byte >> 4
    ihl = first_byte & 0x0F
    ip_header_length = ihl * 4
    service_type = unpacked_data[1]
    total_length = unpacked_data[2]
    identification = unpacked_data[3]
    flags_fragment_offset = unpacked_data[4]
    ttl = unpacked_data[5]
    protocol = unpacked_data[6]
    checksum = unpacked_data[7]
    src_address = socket.inet_ntoa(unpacked_data[8])
    dest_address = socket.inet_ntoa(unpacked_data[9])
    time = datetime.now()

    if DEBUG:
        print(" - Data e Hora de Captura:", time)
        print(" - Endereço de Destino:", dest_address)
        print(" - Versão:", version)
        print(" - IHL:", ihl)
        print(" - Tamanho do Cabeçalho IP:", ip_header_length)
        print(" - Tipo de Serviço:", service_type)
        print(" - Tamanho Total:", total_length)
        print(" - Identificação:", identification)
        print(" - Flags e Fragment Offset:", flags_fragment_offset)
        print(" - TTL:", ttl)
        print(" - Protocolo:", protocol)
        print(" - Checksum:", checksum)
        print(" - Endereço de Origem:", src_address)
        print(" - Endereço de Destino:", dest_address)

    return {
        "date": time,
        "name": "IPv4",
        "src": src_address,
        "dest": dest_address,
        "protocol": protocol,
        "total_length": total_length,
        "header_length": ip_header_length
    }

def unpack_ipv6(packet):
    unpacked_data = struct.unpack('!IHBB16s16s', packet[0:40])

    first_byte = unpacked_data[0]
    version = (first_byte >> 28) & 0x0F
    traffic_class = (first_byte >> 20) & 0xFF
    flow_label = first_byte & 0xFFFFF
    payload_length = unpacked_data[1]
    next_header = unpacked_data[2]
    hop_limit = unpacked_data[3]
    src_address = socket.inet_ntop(socket.AF_INET6, unpacked_data[4])
    dest_address = socket.inet_ntop(socket.AF_INET6, unpacked_data[5])
    time = datetime.now()

    if DEBUG:
        print(" - Data e Hora de Captura:", time)
        print(" - Versão:", version)
        print(" - Classe de Tráfego:", traffic_class)
        print(" - Rótulo de Fluxo:", flow_label)
        print(" - Tamanho do Payload:", payload_length)
        print(" - Próximo Cabeçalho:", next_header)
        print(" - Hop Limit:", hop_limit)
        print(" - Endereço de Origem:", src_address)
        print(" - Endereço de Destino:", dest_address)

    return {
        "date": time,
        "name": "IPv6",
        "src": src_address,
        "dest": dest_address,
        "protocol": next_header,
        "total_length": payload_length + 40,
        "header_length": 40
    }

def unpack_icmp(packet, initial, name):
    unpacked_data = struct.unpack('!BBH', packet[initial:initial+4])

    icmp_type = unpacked_data[0]
    code = unpacked_data[1]
    checksum = unpacked_data[2]
    time = datetime.now()

    if DEBUG:
        print(" - Data e Hora de Captura:", time)
        print(" - ICMP Type:", icmp_type)
        print(" - Code:", code)
        print(" - Checksum:", checksum)

    return {
        "date": time,
        "name": name,
        "total_length": 84,
        "info_str": f"Type: {icmp_type} Code: {code}"
    }

# ---- Camada de Transporte --

def unpack_tcp(packet, initial):
    unpacked_data = struct.unpack('!HHIIHHHH', packet[initial:initial+20])

    src_port = unpacked_data[0]
    dest_port = unpacked_data[1]
    seq_number = unpacked_data[2]
    ack_number = unpacked_data[3]
    data_offset = (unpacked_data[4] >> 12)
    header_length = data_offset * 4
    flags = unpacked_data[4] & 0x1FF
    window_size = unpacked_data[5]
    checksum = unpacked_data[6]
    urgent_pointer = unpacked_data[7]
    time = datetime.now()

    if DEBUG:
        print(" - Data e Hora de Captura:", time)
        print(" - Porta de Origem:", src_port)
        print(" - Porta de Destino:", dest_port)
        print(" - Número de Sequência:", seq_number)
        print(" - Número de Acknowledgment:", ack_number)
        print(" - Data Offset:", data_offset)
        print(" - Tamanho do Cabeçalho TCP:", header_length)
        print(" - Flags:", flags)
        print(" - Tamanho da Janela:", window_size)
        print(" - Checksum:", checksum)
        print(" - Ponteiro Urgente:", urgent_pointer)

    return {
        "date": time,
        "name": "TCP",
        "src_port": src_port,
        "dest_port": dest_port,
        "total_length": header_length
    }

def unpack_udp(packet, initial):
    unpacked_data = struct.unpack('!HHHH', packet[initial:initial+8])

    src_port = unpacked_data[0]
    dest_port = unpacked_data[1]
    length = unpacked_data[2]
    checksum = unpacked_data[3]
    time = datetime.now()

    if DEBUG:
        print(" - Data e Hora de Captura:", time)
        print(" - Porta de Origem:", src_port)
        print(" - Porta de Destino:", dest_port)
        print(" - Tamanho:", length)
        print(" - Checksum:", checksum)

    return {
        "date": time,
        "name": "UDP",
        "src_port": src_port,
        "dest_port": dest_port,
        "total_length": length
    }

# ---- Camada de Aplicação --

def unpack_http(packet, initial, name):
    try:
        payload = packet[initial:]

        if not payload:
            if DEBUG:
                print(" - Pacote TCP na porta 80 sem payload (provável ACK). Ignorando.")
            return None

        if not (payload.startswith(b'HTTP/') or 
                payload.startswith(b'GET ') or 
                payload.startswith(b'POST ') or
                payload.startswith(b'PUT ') or
                payload.startswith(b'DELETE ') or
                payload.startswith(b'HEAD ')):
            
            if DEBUG:
                print(" - Pacote TCP na porta 80, mas não é o início de um cabeçalho HTTP (provável segmento de dados). Ignorando.")
            return None

        header_end = payload.find(b'\r\n\r\n')
        if header_end == -1:
            if DEBUG:
                print(" - Pacote parece HTTP, mas não foi possível encontrar o fim do cabeçalho (provável fragmentação do próprio cabeçalho).")
            return None
        
        header_data = payload[:header_end].decode('iso-8859-1')
        header_lines = header_data.split('\r\n')
        request_line = header_lines[0]
        
        time = datetime.now()
        
        if DEBUG:
            print(" - Data e Hora de Captura:", time)
            print(" - Linha de Requisição/Status:", request_line)
            for line in header_lines:
                if line:
                    print(f"   - {line}")

        return {
            "date": time,
            "name": name,
            "total_length": header_end + 4,
            "request_line": request_line
        }
    except Exception as e:
        if DEBUG:
            print(f" - Erro ao decodificar HTTP: {e}")
        return None

def unpack_dns(packet, initial, name):
    header_size = 12
    unpacked_data = struct.unpack('!HHHHHH', packet[initial:initial + header_size])
    
    transaction_id = unpacked_data[0]
    flags = unpacked_data[1]
    questions = unpacked_data[2]
    answers = unpacked_data[3]
    authorities = unpacked_data[4]
    additional = unpacked_data[5]
    time = datetime.now()

    if DEBUG:
        print(" - Data e Hora de Captura:", time)
        print(" - Transaction ID:", transaction_id)
        print(" - Flags:", hex(flags))
        print(" - Questions:", questions)
        print(" - Answer RRs:", answers)
        print(" - Authority RRs:", authorities)
        print(" - Additional RRs:", additional)
        
    return {
        "date": time,
        "name": name,
        "total_length": header_size,
        "transaction_id": transaction_id,
        "questions": questions,
        "answers": answers
    }

def unpack_ntp(packet, initial, name):
    header_size = 48
    unpack_format = '!BBbbII4s'
    unpack_size = struct.calcsize(unpack_format)
    
    unpacked_data = struct.unpack(unpack_format, packet[initial:initial + unpack_size])

    li_vn_mode = unpacked_data[0]
    li = (li_vn_mode >> 6) & 0b11
    vn = (li_vn_mode >> 3) & 0b111
    mode = li_vn_mode & 0b111
    
    stratum = unpacked_data[1]
    poll = unpacked_data[2]
    precision = unpacked_data[3]
    root_delay = unpacked_data[4]
    root_dispersion = unpacked_data[5]
    ref_id = unpacked_data[6]
    time = datetime.now()

    if DEBUG:
        print(" - Data e Hora de Captura:", time)
        print(f" - LI: {li}, Version: {vn}, Mode: {mode}")
        print(" - Stratum:", stratum)
        print(" - Poll:", poll)
        print(" - Precision:", precision)
        print(" - Root Delay:", root_delay)
        print(" - Root Dispersion:", root_dispersion)
        print(" - Reference ID:", ref_id.hex())

    return {
        "date": time,
        "name": name,
        "total_length": header_size,
        "version": vn,
        "stratum": stratum
    }

def unpack_dhcp(packet, initial, name):
    header_size = 240
    
    unpack_format = '!BBBBIHH4s4s4s4s'
    unpack_size = struct.calcsize(unpack_format)
    
    unpacked_data = struct.unpack(unpack_format, packet[initial:initial + unpack_size])
    
    opcode = unpacked_data[0]
    hw_type = unpacked_data[1]
    hw_len = unpacked_data[2]
    hops = unpacked_data[3]
    transaction_id = unpacked_data[4]
    seconds = unpacked_data[5]
    flags = unpacked_data[6]
    client_ip = socket.inet_ntoa(unpacked_data[7])
    your_ip = socket.inet_ntoa(unpacked_data[8])
    server_ip = socket.inet_ntoa(unpacked_data[9])
    gateway_ip = socket.inet_ntoa(unpacked_data[10])
    time = datetime.now()

    if DEBUG:
        print(" - Data e Hora de Captura:", time)
        print(" - Opcode:", "Request (1)" if opcode == 1 else "Reply (2)")
        print(" - Hardware Type:", hw_type)
        print(" - Hardware Addr Len:", hw_len)
        print(" - Hops:", hops)
        print(" - Transaction ID:", transaction_id)
        print(" - Seconds:", seconds)
        print(" - Flags:", hex(flags))
        print(" - Client IP:", client_ip)
        print(" - Your IP:", your_ip)
        print(" - Server IP:", server_ip)
        print(" - Gateway IP:", gateway_ip)

    return {
        "date": time,
        "name": name,
        "total_length": header_size,
        "transaction_id": transaction_id,
        "opcode": opcode
    }

# -- Funções de Escolhas

def get_initial_info(packet):
    print("\n--- Pacote Recebido ---\n")
    print("Informações Gerais")
    print(f" - Tamanho: {len(packet)} bytes")
    print(f" - Dados Brutos (primeiros 60 bytes): {packet[:60]}")

def get_ethernet_data(packet):
    return unpack_ethernet(packet)

def get_ip_data(packet):
    ip_data = None
    
    global IPV4_COUNT, IPV6_COUNT, OTHER_IP_COUNT
    
    if len(packet) < 1: 
        return None
    
    version = packet[0] >> 4
    
    match version:
        case 4:
            if DEBUG:
                print("\nProtocolo IPv4")
            IPV4_COUNT += 1
            ip_data = unpack_ipv4(packet)
        case 6:
            if DEBUG:
                print("\nProtocolo IPv6")   
            IPV6_COUNT += 1
            ip_data = unpack_ipv6(packet)
        case _:
            if DEBUG:
                print(f"\nProtocolo {version} não suportado.")
            OTHER_IP_COUNT += 1
            ip_data = None
                
    return ip_data

def get_transport_data(ip_data, packet):
    transport_data = None
    initial_position = ip_data["header_length"]

    global ICMP_COUNT, TCP_COUNT, UDP_COUNT, OTHER_TRANSPORT_COUNT

    match ip_data["protocol"]:
        case 1:
            if DEBUG:
                print("\nProtocolo ICMP")
            ICMP_COUNT += 1
            transport_data = unpack_icmp(packet, initial_position, "ICMP")
        case 6:
            if DEBUG:
                print("\nProtocolo TCP")
            TCP_COUNT += 1
            transport_data = unpack_tcp(packet, initial_position)
        case 17:
            if DEBUG:
                print("\nProtocolo UDP")
            UDP_COUNT += 1
            transport_data = unpack_udp(packet, initial_position)
        case 58:
            if DEBUG:
                print("\nProtocolo ICMPv6")
            ICMP_COUNT += 1
            transport_data = unpack_icmp(packet, initial_position, "ICMPv6")
        case _:
            if DEBUG:
                print(f"\nProtocolo {ip_data['protocol']} não suportado.")
            OTHER_TRANSPORT_COUNT += 1
            transport_data = None # TODO: Criar um dicionario com informações basicas do outro protocolo para popular o LOG

    return transport_data
    
def get_application_data(transport_data, packet, initial_position):
    application_data = None

    if transport_data["name"] == "TCP":
        initial_position += transport_data["total_length"]
    elif transport_data["name"] == "UDP":
        initial_position += 8
    else:
        return None
    
    global HTTP_COUNT, DNS_COUNT, DHCP_COUNT, NTP_COUNT, OTHER_APP_COUNT
    
    ports = (transport_data.get("src_port"), transport_data.get("dest_port"))
            
    if 80 in ports:
        if DEBUG:
            print("\nProtocolo HTTP")
        HTTP_COUNT += 1
        application_data = unpack_http(packet, initial_position, "HTTP")
    elif 53 in ports:
        if DEBUG:
            print("\nProtocolo DNS")
        DNS_COUNT += 1
        application_data = unpack_dns(packet, initial_position, "DNS")
    elif (67 in ports) or (68 in ports):
        if DEBUG:
            print("\nProtocolo DHCP")
        DHCP_COUNT += 1
        application_data = unpack_dhcp(packet, initial_position, "DHCP")
    elif 123 in ports:
        if DEBUG:
            print("\nProtocolo NTP")
        NTP_COUNT += 1
        application_data = unpack_ntp(packet, initial_position, "NTP")
    else:
        if DEBUG:
            port_in_use = transport_data.get("dest_port") or transport_data.get("src_port")
            print(f"\nProtocolo na porta {port_in_use} não suportado.")
        OTHER_APP_COUNT += 1
        application_data = None # TODO: Criar um dicionario com informações basicas do outro protocolo para popular o LOG
                
    return application_data

# -- Função Principal --
def main():
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    except PermissionError:
        print("Lembre-se de executar este script com sudo:")
        return
    except OSError as e:
        print(f"Erro de OS: {e}")
        print(f"Verifique se o nome da interface '{INTERFACE}' está correto.")
        return

    s.bind((INTERFACE, 0))
    
    print(f"[*] Escutando na interface {INTERFACE}...")

    try:
        while True:
            raw_packet, _ = s.recvfrom(65535)

            if DEBUG:
                get_initial_info(raw_packet)

            # ether_data = get_ethernet_data(raw_packet)

            ip_data = get_ip_data(raw_packet)
            if not ip_data:
                continue    
            
            transport_data = get_transport_data(ip_data, raw_packet) 
            
            application_data = None
            if transport_data and transport_data["name"] not in ["ICMP", "ICMPv6"]:
                application_data = get_application_data(transport_data, raw_packet, ip_data["header_length"])
            
            save_logs(ip_data, transport_data, application_data)
            
            if not DEBUG:
                monitor_interface()
 
    except KeyboardInterrupt:
        print("\n[*] Monitoramento encerrado.")
    finally:
        s.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: sudo python monitor.py [interface] [debug on/off]")
        sys.exit(1)

    INTERFACE = sys.argv[1]
    
    if len(sys.argv) == 3:
        if sys.argv[2] == "on":
            DEBUG = True
        elif sys.argv[2] == "off":
            DEBUG = False
        else:
            print("Uso: sudo python monitor.py [interface] [debug on/off]")
            sys.exit(1)

    main()
