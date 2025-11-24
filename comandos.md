# 1. Reconstrói e sobe os containers (sniffer e client)
docker-compose up --build

# 2. Inicia um servidor HTTP silencioso na porta 80 do sniffer
docker exec -d sniffer python -m http.server 80

# 3. Entra no shell do container 'client'
docker exec -it client sh

# 4. Instala todas as ferramentas necessárias (curl, dig, nc) de uma vez
apk add curl bind-tools netcat-openbsd

# --- Teste 1: ICMP (Ping IPv4) ---
### Gera logs em: camada_internet.csv
ping -4 -c 4 sniffer

# --- Teste 2: HTTP (TCP Porta 80) ---
### Gera logs em: camada_transporte.csv e camada_aplicacao.csv
curl http://sniffer/

# --- Teste 3: DNS (UDP Porta 53) ---
### Gera logs em: camada_transporte.csv e camada_aplicacao.csv
dig @sniffer google.com

# --- Teste 4: NTP (UDP Porta 123) ---
## Envia pacote fake de 48 bytes para não travar o unpack do Python
### Gera logs em: camada_aplicacao.csv
dd if=/dev/zero bs=48 count=1 | nc -u sniffer 123

# --- Teste 5: Tráfego Genérico (UDP) ---
### Gera logs em: camada_transporte.csv (UDP)
echo "Teste UDP Generico" | nc -u sniffer 9090

# --- Teste 6: IPv6 (ICMPv6) ---
### Gera logs em: camada_internet.csv (IPv6)
ping -6 -c 4 2001:db8:1::100