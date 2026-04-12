#!/bin/bash
# SOCbox Web — Instalador
# Roda no servidor Wazuh (Ubuntu Server)
# Após instalar: acesse http://192.168.0.10:8888

set -e
GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  SOCbox Wazuh Response Platform          ║"
echo "  ║  Web Edition v3.0 — Instalador           ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${NC}"

INSTALL_DIR="/opt/socboxwazuh"

echo -e "${YELLOW}[1/4] Instalando dependências...${NC}"
apt-get update -qq
apt-get install -y python3 python3-pip git 2>/dev/null
pip3 install flask requests --break-system-packages -q
echo -e "${GREEN}  ✓ Flask + requests instalados${NC}"

echo -e "${YELLOW}[2/4] Instalando arquivos...${NC}"
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/templates"
cp app.py "$INSTALL_DIR/app.py"
cp templates/index.html "$INSTALL_DIR/templates/index.html"
echo -e "${GREEN}  ✓ Arquivos em $INSTALL_DIR${NC}"

echo -e "${YELLOW}[3/4] Criando comando 'socboxwazuh'...${NC}"
cat > /usr/local/bin/socboxwazuh << 'LAUNCHER'
#!/bin/bash
cd /opt/socboxwazuh
python3 app.py
LAUNCHER
chmod +x /usr/local/bin/socboxwazuh
echo -e "${GREEN}  ✓ Comando 'socboxwazuh' criado${NC}"

echo -e "${YELLOW}[4/4] Criando serviço systemd (autostart)...${NC}"
cat > /etc/systemd/system/socboxwazuh.service << 'SERVICE'
[Unit]
Description=SOCbox Wazuh Response Platform
After=network.target wazuh-manager.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/socboxwazuh/app.py
WorkingDirectory=/opt/socboxwazuh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE
systemctl daemon-reload
systemctl enable socboxwazuh 2>/dev/null || true
echo -e "${GREEN}  ✓ Serviço systemd configurado${NC}"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Instalação concluída!                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Iniciar agora:   ${CYAN}socboxwazuh${NC}"
echo -e "  Como serviço:    ${CYAN}systemctl start socboxwazuh${NC}"
echo -e "  Acessar:         ${CYAN}http://$(hostname -I | awk '{print $1}'):8888${NC}"
echo ""
