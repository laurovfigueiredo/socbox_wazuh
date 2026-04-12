# ◈ SOCbox — Wazuh Response Platform (Web Edition)

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)
![Flask](https://img.shields.io/badge/Flask-3.x-black?style=flat-square)
![Wazuh](https://img.shields.io/badge/Wazuh-4.x-005571?style=flat-square)
![Platform](https://img.shields.io/badge/Runs%20on-Ubuntu%20Server-orange?style=flat-square)

**Plataforma web de resposta a incidentes com integração Wazuh.**
Roda no servidor Wazuh e é acessada pelo navegador de qualquer máquina da rede.

## Instalação no servidor Wazuh (192.168.0.10)

```bash
git clone https://github.com/laurovfigueiredo/socboxwazuh.git
cd socboxwazuh
bash install.sh
```

## Acessar pelo Kali ou qualquer máquina da rede

```bash
# Apenas abra o navegador em:
http://192.168.0.10:8888
```

## Iniciar / Parar

```bash
# Comando direto
socboxwazuh

# Como serviço (inicia automático com o servidor)
systemctl start socboxwazuh
systemctl stop socboxwazuh
systemctl status socboxwazuh
```

## Configurar conexão Wazuh

Clique em **⚙ Configurar** na interface e preencha:

| Campo | Valor |
|---|---|
| Manager Host | `127.0.0.1` (localhost — roda no próprio servidor) |
| Manager Porta | `55000` |
| Manager Usuário | usuário da API Wazuh |
| Manager Senha | senha da API Wazuh |
| Indexer Host | `127.0.0.1` |
| Indexer Porta | `9200` |
| Indexer Usuário | `admin` |
| Indexer Senha | senha do OpenSearch |
| Modo DEMO | desmarcar para dados reais |

Use **🔌 Testar Conexão** para validar antes de salvar.

## Desinstalar

```bash
systemctl stop socboxwazuh
systemctl disable socboxwazuh
rm -rf /opt/socboxwazuh /usr/local/bin/socboxwazuh /etc/systemd/system/socboxwazuh.service
systemctl daemon-reload
```

## Arquitetura

```
Servidor Wazuh (192.168.0.10)
├── Wazuh Manager API    :55000
├── Wazuh Indexer        :9200
└── SOCbox Web           :8888  ← Flask app

Kali Linux (192.168.0.236)
└── Navegador → http://192.168.0.10:8888
```

## Requisitos
- Ubuntu Server 20.04+ / Debian 11+
- Python 3.10+
- Wazuh 4.x instalado
- Porta 8888 liberada no firewall
