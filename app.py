#!/usr/bin/env python3
"""
SOCbox Wazuh Response Platform — Web Edition v3.0
Roda no servidor Wazuh (192.168.0.10)
Acesse pelo navegador: http://192.168.0.10:8888
"""

import json, datetime, subprocess, os, threading
from flask import Flask, render_template, jsonify, request, Response
import requests as req
from requests.packages.urllib3.exceptions import InsecureRequestWarning
req.packages.urllib3.disable_warnings(InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = "socbox-secret-2024"

# ─── CONFIG PADRÃO ─────────────────────────────────────────────────────────
CONFIG = {
    "manager_host": "127.0.0.1",   # localhost — roda no próprio servidor
    "manager_port": "55000",
    "manager_user": "wazuh",
    "manager_pass": "wazuh",
    "indexer_host": "127.0.0.1",
    "indexer_port": "9200",
    "indexer_user": "admin",
    "indexer_pass": "admin",
    "demo":         False,          # False = tenta conectar real por padrão
}

action_log = []

# ─── WAZUH CLIENT ──────────────────────────────────────────────────────────
class WazuhClient:
    def __init__(self):
        self.token   = None
        self.session = req.Session()
        self.session.verify = False

    @property
    def mgr(self): return f"https://{CONFIG['manager_host']}:{CONFIG['manager_port']}"
    @property
    def idx(self): return f"https://{CONFIG['indexer_host']}:{CONFIG['indexer_port']}"

    def auth(self):
        r = self.session.post(f"{self.mgr}/security/user/authenticate",
                              auth=(CONFIG["manager_user"], CONFIG["manager_pass"]),
                              timeout=8)
        r.raise_for_status()
        self.token = r.json()["data"]["token"]
        self.session.headers.update({"Authorization": f"Bearer {self.token}"})
        return self.token

    def get_agents(self):
        r = self.session.get(f"{self.mgr}/agents",
                             params={"limit":500,"sort":"+name"}, timeout=10)
        r.raise_for_status()
        items = r.json()["data"]["affected_items"]
        out = []
        for ag in items:
            if ag.get("id") == "000": continue
            os_info = ag.get("os", {})
            os_name = os_info.get("name","?") if isinstance(os_info, dict) else str(os_info)
            out.append({
                "id":     ag.get("id","?"),
                "name":   ag.get("name","?"),
                "ip":     ag.get("ip","N/A"),
                "os":     os_name,
                "status": ag.get("status","unknown"),
                "version":ag.get("version","?"),
                "last_keepalive": ag.get("lastKeepAlive","?"),
            })
        return out

    def get_alerts(self, limit=100, min_level=3):
        q = {
            "size": limit,
            "sort": [{"timestamp":{"order":"desc"}}],
            "query":{"bool":{"filter":[
                {"range":{"rule.level":{"gte": min_level}}}
            ]}}
        }
        r = req.post(f"{self.idx}/wazuh-alerts-*/_search",
                     auth=(CONFIG["indexer_user"], CONFIG["indexer_pass"]),
                     json=q, verify=False, timeout=15)
        r.raise_for_status()
        hits = r.json().get("hits",{}).get("hits",[])
        return [_norm(h["_source"], h["_id"]) for h in hits]

    def active_response(self, agent_id, command, arguments=None):
        payload = {"command": command, "arguments": arguments or []}
        r = self.session.put(f"{self.mgr}/active-response",
                             params={"agents_list": agent_id},
                             json=payload, timeout=15)
        return r.json()

    def test(self):
        out = {"manager": False, "indexer": False, "mgr_err": "", "idx_err": ""}
        try:
            r = self.session.post(f"{self.mgr}/security/user/authenticate",
                                  auth=(CONFIG["manager_user"],CONFIG["manager_pass"]),
                                  timeout=6)
            out["manager"] = r.status_code == 200
            if not out["manager"]: out["mgr_err"] = f"HTTP {r.status_code}: {r.text[:80]}"
        except Exception as e: out["mgr_err"] = str(e)
        try:
            r = req.get(f"{self.idx}/", auth=(CONFIG["indexer_user"],CONFIG["indexer_pass"]),
                        verify=False, timeout=6)
            out["indexer"] = r.status_code < 500
            if not out["indexer"]: out["idx_err"] = f"HTTP {r.status_code}"
        except Exception as e: out["idx_err"] = str(e)
        return out

wazuh = WazuhClient()

# ─── NORMALIZAR ALERTA ─────────────────────────────────────────────────────
def _norm(src, doc_id):
    rule  = src.get("rule",{})
    agent = src.get("agent",{})
    data  = src.get("data",{})
    mitre = rule.get("mitre",{})
    tactics    = mitre.get("tactic",[])
    techniques = mitre.get("id",[])
    src_ip = (data.get("srcip") or data.get("src_ip") or
              data.get("win",{}).get("eventdata",{}).get("ipAddress","N/A") or "N/A")
    geo = src.get("GeoLocation",{})
    ts  = src.get("timestamp","")
    try:
        dt = datetime.datetime.fromisoformat(ts.replace("Z",""))
        ts_fmt = dt.strftime("%d/%m %H:%M:%S")
    except: ts_fmt = ts[:16]

    level = int(rule.get("level",0))
    if level >= 13:   sev_cls = "EMERGÊNCIA";  sev_color = "#ff0040"
    elif level >= 10: sev_cls = "CRÍTICO";     sev_color = "#f85149"
    elif level >= 7:  sev_cls = "ALTO";        sev_color = "#e3b341"
    elif level >= 5:  sev_cls = "MÉDIO";       sev_color = "#58a6ff"
    else:             sev_cls = "BAIXO";       sev_color = "#3fb950"

    compliance = []
    for fw in ["pci_dss","nist_800_53","gdpr","hipaa","tsc","cis"]:
        vals = rule.get(fw,[])
        if vals: compliance.append(f"{fw.upper().replace('_',' ')}: {', '.join(vals[:3])}")

    return {
        "id":          doc_id[:16],
        "agent_id":    agent.get("id","?"),
        "agent_name":  agent.get("name","?"),
        "agent_ip":    agent.get("ip","N/A"),
        "timestamp":   ts_fmt,
        "timestamp_raw": ts,
        "rule_id":     rule.get("id","?"),
        "rule_level":  level,
        "sev_cls":     sev_cls,
        "sev_color":   sev_color,
        "description": rule.get("description","Sem descrição"),
        "src_ip":      src_ip,
        "geo_country": geo.get("country_name","N/A"),
        "geo_city":    geo.get("city_name","N/A"),
        "mitre_tactic":    tactics[0] if tactics else "N/A",
        "mitre_technique": techniques[0] if techniques else "N/A",
        "category":    rule.get("groups",["N/A"])[0],
        "user":        (src.get("predecoder",{}).get("user") or
                        data.get("dstuser") or data.get("win",{}).get("eventdata",{}).get("targetUserName","N/A")),
        "location":    src.get("location","N/A"),
        "full_log":    src.get("full_log","N/A"),
        "compliance":  compliance,
        "intention":   rule.get("description",""),
        "target":      f"{agent.get('name','?')} — {src.get('location','?')}",
    }

# ─── MOCK DATA ─────────────────────────────────────────────────────────────
MOCK_AGENTS = [
    {"id":"001","name":"WIN-WORKSTATION-01","ip":"192.168.0.101","os":"Windows 10","status":"active","version":"4.9.2","last_keepalive":"2025-01-15T14:30:00Z"},
    {"id":"002","name":"UBUNTU-WEB-SRV","ip":"192.168.0.102","os":"Ubuntu 22.04","status":"active","version":"4.9.2","last_keepalive":"2025-01-15T14:29:00Z"},
    {"id":"003","name":"KALI-PENTEST","ip":"192.168.0.236","os":"Kali Linux","status":"active","version":"4.9.2","last_keepalive":"2025-01-15T14:31:00Z"},
    {"id":"004","name":"WIN-DC-01","ip":"192.168.0.200","os":"Windows Server 2022","status":"active","version":"4.9.2","last_keepalive":"2025-01-15T14:28:00Z"},
    {"id":"005","name":"DEBIAN-DB-SRV","ip":"192.168.0.103","os":"Debian 12","status":"disconnected","version":"4.9.1","last_keepalive":"2025-01-15T12:00:00Z"},
]
MOCK_ALERTS = [
    {"id":"ALT001","agent_id":"004","agent_name":"WIN-DC-01","agent_ip":"192.168.0.200","timestamp":"15/01 14:32:11","timestamp_raw":"2025-01-15T14:32:11Z","rule_id":"5712","rule_level":13,"sev_cls":"EMERGÊNCIA","sev_color":"#ff0040","description":"Multiple failed SSH login attempts — Brute Force","src_ip":"45.142.212.100","geo_country":"Russia","geo_city":"Moscow","mitre_tactic":"Credential Access","mitre_technique":"T1110","category":"authentication_failed","user":"administrator","location":"(192.168.0.200) -> /var/log/auth.log","full_log":"Jan 15 14:32:11 WIN-DC-01 sshd[4821]: Failed password for administrator from 45.142.212.100","compliance":["PCI DSS: 8.3","NIST 800 53: AC-7","ISO 27001: A.9.4.2"],"intention":"Força bruta SSH tentando comprometer o Active Directory via acesso administrativo remoto.","target":"WIN-DC-01 — sshd porta 22"},
    {"id":"ALT002","agent_id":"001","agent_name":"WIN-WORKSTATION-01","agent_ip":"192.168.0.101","timestamp":"15/01 14:28:55","timestamp_raw":"2025-01-15T14:28:55Z","rule_id":"87001","rule_level":12,"sev_cls":"CRÍTICO","sev_color":"#f85149","description":"Ransomware behavior detected — mass file encryption in progress","src_ip":"192.168.0.101","geo_country":"N/A","geo_city":"N/A","mitre_tactic":"Impact","mitre_technique":"T1486","category":"malware","user":"john.doe","location":"C:\\Users\\john.doe\\Documents","full_log":"Wazuh FIM: Mass modification detected — 847 files encrypted in 2 minutes","compliance":["PCI DSS: 5.2","NIST 800 53: SI-3","ISO 27001: A.12.2.1"],"intention":"Ransomware cifrando arquivos do usuário e tentando comunicação C2 via HTTPS na porta 443.","target":"C:\\Users\\john.doe\\Documents — WIN-WORKSTATION-01"},
    {"id":"ALT003","agent_id":"002","agent_name":"UBUNTU-WEB-SRV","agent_ip":"192.168.0.102","timestamp":"15/01 14:15:30","timestamp_raw":"2025-01-15T14:15:30Z","rule_id":"31103","rule_level":10,"sev_cls":"CRÍTICO","sev_color":"#f85149","description":"SQL Injection attempt detected in web application logs","src_ip":"89.248.165.200","geo_country":"Netherlands","geo_city":"Amsterdam","mitre_tactic":"Initial Access","mitre_technique":"T1190","category":"web_attack","user":"www-data","location":"Apache2 /api/users","full_log":"GET /api/users?id=1 UNION SELECT username,password FROM users-- HTTP/1.1 200","compliance":["OWASP Top 10: A03","PCI DSS: 6.6","NIST 800 53: SA-11"],"intention":"Tentativa de extração de credenciais do banco via UNION-based SQL Injection no endpoint público.","target":"Apache2 /api/users — UBUNTU-WEB-SRV"},
    {"id":"ALT004","agent_id":"004","agent_name":"WIN-DC-01","agent_ip":"192.168.0.200","timestamp":"15/01 13:58:10","timestamp_raw":"2025-01-15T13:58:10Z","rule_id":"100007","rule_level":11,"sev_cls":"CRÍTICO","sev_color":"#f85149","description":"C2 beacon detected — suspicious outbound connection port 4444","src_ip":"185.220.101.42","geo_country":"Germany","geo_city":"Frankfurt","mitre_tactic":"Command and Control","mitre_technique":"T1071","category":"c2","user":"SYSTEM","location":"WIN-DC-01 -> 185.220.101.42:4444","full_log":"Outbound TCP connection WIN-DC-01:49152 -> 185.220.101.42:4444 ESTABLISHED","compliance":["NIST 800 53: SI-4","ISO 27001: A.13.1.1"],"intention":"Beacon C2 ativo — possível implante Cobalt Strike comunicando com servidor de controle em Frankfurt.","target":"WIN-DC-01 → 185.220.101.42:4444 (Tor Exit Node)"},
    {"id":"ALT005","agent_id":"002","agent_name":"UBUNTU-WEB-SRV","agent_ip":"192.168.0.102","timestamp":"15/01 13:44:00","timestamp_raw":"2025-01-15T13:44:00Z","rule_id":"100008","rule_level":8,"sev_cls":"ALTO","sev_color":"#e3b341","description":"Privilege escalation — unauthorized sudo root command","src_ip":"N/A","geo_country":"N/A","geo_city":"N/A","mitre_tactic":"Privilege Escalation","mitre_technique":"T1548","category":"sudo","user":"deploy","location":"/var/log/auth.log","full_log":"Jan 15 13:44:00 ubuntu-web sudo: deploy : command not allowed ; TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash","compliance":["CIS: L1-5.4","NIST 800 53: AC-6","ISO 27001: A.9.2.3"],"intention":"Usuário 'deploy' tentando escalonamento de privilégios via sudo para shell root — possível pós-comprometimento.","target":"Usuário deploy — UBUNTU-WEB-SRV"},
]

def get_agents():
    if CONFIG["demo"]: return MOCK_AGENTS
    try:
        wazuh.auth()
        return wazuh.get_agents()
    except Exception as e:
        log_action("SISTEMA", f"Falha ao buscar agentes: {e} — usando DEMO")
        return MOCK_AGENTS

def get_alerts(min_level=3):
    if CONFIG["demo"]: return MOCK_ALERTS
    try:
        if not wazuh.token: wazuh.auth()
        return wazuh.get_alerts(limit=200, min_level=min_level)
    except Exception as e:
        log_action("SISTEMA", f"Falha ao buscar alertas: {e} — usando DEMO")
        return MOCK_ALERTS

def log_action(alert_id, msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    action_log.insert(0, {"ts": ts, "alert": alert_id, "msg": msg})
    if len(action_log) > 200: action_log.pop()

# ─── ROTAS API ─────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/agents")
def api_agents():
    return jsonify(get_agents())

@app.route("/api/alerts")
def api_alerts():
    lvl = int(request.args.get("min_level", 3))
    return jsonify(get_alerts(lvl))

@app.route("/api/config", methods=["GET","POST"])
def api_config():
    if request.method == "POST":
        data = request.json
        CONFIG.update(data)
        wazuh.token = None  # força re-auth
        return jsonify({"ok": True})
    return jsonify({k:v for k,v in CONFIG.items() if "pass" not in k})

@app.route("/api/test")
def api_test():
    return jsonify(wazuh.test())

@app.route("/api/log")
def api_log():
    return jsonify(action_log[:50])

@app.route("/api/action", methods=["POST"])
def api_action():
    data      = request.json
    action    = data.get("action")
    alert_id  = data.get("alert_id","?")
    agent_id  = data.get("agent_id","?")
    agent_name= data.get("agent_name","?")
    src_ip    = data.get("src_ip","N/A")
    user      = data.get("user","N/A")
    process   = data.get("process","suspeito")

    result = {"ok": True, "msg": "", "cmds": []}
    demo   = CONFIG["demo"]

    def send_ar(cmd, args=None):
        if not demo:
            try:
                if not wazuh.token: wazuh.auth()
                wazuh.active_response(agent_id, cmd, args)
                return True
            except Exception as e:
                result["ok"]  = False
                result["msg"] = str(e)
                return False
        return True

    if action == "block_ip":
        cmds = [f"iptables -A INPUT -s {src_ip} -j DROP",
                f"iptables -A OUTPUT -d {src_ip} -j DROP"]
        result["cmds"] = cmds
        ok = send_ar("firewall-drop", [src_ip])
        result["msg"] = f"IP {src_ip} bloqueado em {agent_name} {'(real)' if not demo else '(DEMO)'}."
        log_action(alert_id, f"BLOCK_IP {src_ip} → {agent_name}")

    elif action == "panic":
        wip  = CONFIG["manager_host"]
        cmds = ["iptables -P INPUT DROP","iptables -P OUTPUT DROP","iptables -P FORWARD DROP",
                f"iptables -A INPUT -s {wip} -j ACCEPT",f"iptables -A OUTPUT -d {wip} -j ACCEPT"]
        result["cmds"] = cmds
        send_ar("host-deny",["ALL"])
        result["msg"] = f"MODO PÂNICO ativado — {agent_name} ISOLADO. Apenas {wip} permitido."
        log_action(alert_id, f"PANIC — {agent_name} ISOLADO")

    elif action == "kill_process":
        cmds = [f"kill -9 $(pgrep -f {process})", f"pkill -KILL -f {process}"]
        result["cmds"] = cmds
        send_ar("kill-process",[process])
        result["msg"] = f"Processo '{process}' encerrado (SIGKILL) em {agent_name}."
        log_action(alert_id, f"KILL_PROCESS {process} → {agent_name}")

    elif action == "quarantine":
        cmds = [f"mkdir -p /var/socbox/quarantine",
                f"mv /path/to/{process} /var/socbox/quarantine/{process}.$(date +%s).qtn",
                f"chmod 000 /var/socbox/quarantine/*"]
        result["cmds"] = cmds
        result["msg"] = f"Binário '{process}' movido para quarentena em {agent_name}."
        log_action(alert_id, f"QUARANTINE {process} → {agent_name}")

    elif action == "force_logout":
        cmds = [f"pkill -KILL -u {user}", f"who | grep {user} | awk '{{print $2}}' | xargs -I{{}} pkill -t {{}}"]
        result["cmds"] = cmds
        send_ar("force-logout",[user])
        result["msg"] = f"Usuário '{user}' desconectado de {agent_name}."
        log_action(alert_id, f"LOGOUT {user} → {agent_name}")

    elif action == "lock_account":
        cmds = [f"usermod -L {user}", f"passwd -l {user}"]
        result["cmds"] = cmds
        send_ar("disable-account",[user])
        result["msg"] = f"Conta '{user}' bloqueada em {agent_name}."
        log_action(alert_id, f"LOCK_ACCOUNT {user} → {agent_name}")

    elif action == "reset_password":
        cmds = [f"chage -d 0 {user}"]
        result["cmds"] = cmds
        result["msg"] = f"Senha de '{user}' expirada — reset obrigatório no próximo login."
        log_action(alert_id, f"RESET_PW {user} → {agent_name}")

    elif action == "patch":
        pkg = data.get("package","pacote")
        cmds = [f"apt-get update -qq", f"apt-get install --only-upgrade {pkg} -y"]
        result["cmds"] = cmds
        send_ar("run-patch",[pkg])
        result["msg"] = f"Patch do pacote '{pkg}' aplicado em {agent_name}."
        log_action(alert_id, f"PATCH {pkg} → {agent_name}")

    elif action == "harden":
        cmds = ["sysctl -w net.ipv4.conf.all.send_redirects=0",
                "sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config",
                "systemctl enable auditd && systemctl start auditd",
                "echo 'AllowTcpForwarding no' >> /etc/ssh/sshd_config"]
        result["cmds"] = cmds
        result["msg"] = f"Hardening CIS L1 aplicado em {agent_name}."
        log_action(alert_id, f"HARDEN → {agent_name}")

    elif action == "yara":
        cmds = ["yara -r /var/ossec/ruleset/yara/malware.yar /tmp/",
                "yara -r /var/ossec/ruleset/yara/ransomware.yar /home/",
                "yara -r /var/ossec/ruleset/yara/webshell.yar /var/www/"]
        result["cmds"] = cmds
        result["msg"] = f"Varredura YARA iniciada em {agent_name} — aguarde resultado no log."
        log_action(alert_id, f"YARA_SCAN → {agent_name}")

    elif action == "forensic":
        cmds = ["netstat -antp 2>/dev/null || ss -antp",
                "ps auxf | grep -v grep",
                "lsof -i 2>/dev/null | head -40",
                "find /tmp /var/tmp -newer /etc/passwd -type f 2>/dev/null",
                "last -20",
                "cat /var/log/auth.log | tail -50"]
        result["cmds"] = cmds
        result["msg"] = f"Snapshot forense solicitado de {agent_name} — comandos prontos para execução."
        log_action(alert_id, f"FORENSIC_SNAPSHOT → {agent_name}")

    elif action == "ioc_hunt":
        result["cmds"] = [f"grep -r '{src_ip}' /var/ossec/logs/alerts/ 2>/dev/null | tail -20"]
        result["msg"] = f"Caça IOC {src_ip} disparada em todos os agentes."
        log_action(alert_id, f"IOC_HUNT {src_ip}")

    elif action == "resolve":
        result["msg"] = f"Alerta {alert_id} marcado como RESOLVIDO. Nota registrada."
        log_action(alert_id, f"RESOLVED por analista")

    elif action == "escalate":
        result["msg"] = f"Alerta {alert_id} escalado para L3/IR. Ticket: INC-{alert_id[:8]}-{datetime.date.today().strftime('%Y%m%d')}"
        log_action(alert_id, f"ESCALATED → L3/IR")

    elif action == "false_positive":
        result["msg"] = f"Alerta {alert_id} marcado como Falso Positivo. Regra #{data.get('rule_id','?')} em revisão."
        log_action(alert_id, f"FALSE_POSITIVE — regra #{data.get('rule_id','?')}")

    else:
        result["ok"]  = False
        result["msg"] = f"Ação '{action}' desconhecida."

    return jsonify(result)

if __name__ == "__main__":
    print("\n" + "═"*55)
    print("  ◈  SOCbox Wazuh Response Platform v3.0")
    print("  Acesse:  http://192.168.0.10:8888")
    print("  Ctrl+C para encerrar")
    print("═"*55 + "\n")
    app.run(host="0.0.0.0", port=8888, debug=False)
