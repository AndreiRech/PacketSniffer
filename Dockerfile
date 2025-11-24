# Usa uma imagem leve do Python
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

# Define o diretório de trabalho dentro do container
WORKDIR /app

# Copia o seu script para dentro da imagem
COPY monitor.py .

# Cria o diretório de logs para evitar erros de permissão
RUN mkdir -p Logs

# O comando padrão deixa o container rodando, mas iremos sobrescrever no Compose
CMD ["python3", "monitor.py", "eth0", "off"]