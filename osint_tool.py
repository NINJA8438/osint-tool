import os
import socket
import whois
import dns.resolver
import requests
import time
from stem import Signal
from stem.control import Controller
from urllib.parse import urlparse
import socks
import concurrent.futures
import json

# Configurar proxy Tor
socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
socket.socket = socks.socksocket

def renew_tor_connection():
    """Renovar circuito Tor para novo endereço IP"""
    with Controller.from_port(port=9051) as controller:
        controller.authenticate(password="")
        controller.signal(Signal.NEWNYM)
        time.sleep(5)  # Esperar circuito ser estabelecido

def get_tor_session():
    """Criar sessão requests com proxy Tor"""
    session = requests.Session()
    session.proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
    return session

def banner():
    print("""
     ██████╗ ███████╗██╗███╗   ██╗████████╗
    ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
    ██║   ██║█████╗  ██║██╔██╗ ██║   ██║   
    ██║   ██║██╔══╝  ██║██║╚██╗██║   ██║   
    ╚██████╔╝██║     ██║██║ ╚████║   ██║   
     ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝   ╚═╝   
        OSINT Recon Tool - Modo Anônimo
    """)
    print("Conectado através da rede Tor")

def whois_lookup(domain, session):
    print("\n[+] WHOIS Lookup via Tor...")
    try:
        # Usar serviço WHOIS via proxy
        url = f"https://www.whois.com/whois/{domain}"
        response = session.get(url, timeout=15)
        print(f"Status: {response.status_code}")
        print("Verifique manualmente em:", url)
    except Exception as e:
        print(f"Erro: {e}")

def dns_lookup(domain):
    print("\n[+] DNS Records via Tor...")
    try:
        # Usar DNS público via Tor
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['9.9.9.9']  # Quad9 DNS sobre Tor
        records = ['A', 'MX', 'NS', 'TXT']
        
        for r in records:
            try:
                answers = resolver.resolve(domain, r)
                print(f"\n{r} Records:")
                for answer in answers:
                    print(f"  {answer}")
            except dns.resolver.NoAnswer:
                pass
    except Exception as e:
        print(f"Erro: {e}")

def subdomain_enum(domain, session):
    print("\n[+] Subdomain Enumeration via Tor...")
    subdomains = ["www", "mail", "ftp", "admin", "api", "vpn", "portal"]
    for sub in subdomains:
        full_domain = f"{sub}.{domain}"
        try:
            # Tentar conexão TCP via Tor
            ip = socket.gethostbyname(full_domain)
            print(f"{full_domain} -> {ip}")
        except:
            pass

def leakix_lookup(domain, session):
    print("\n[+] LeakIX Search via Tor...")
    try:
        url = f"https://leakix.net/api/subdomains/{domain}"
        response = session.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            if data:
                print("Subdomínios encontrados:")
                for item in data:
                    print(f"  - {item['subdomain']}")
            else:
                print("Nenhum resultado encontrado")
        else:
            print(f"Erro na API: {response.status_code}")
    except Exception as e:
        print(f"Erro: {e}")

def web_scan(domain, session):
    print("\n[+] Web Technologies Scan via Tor...")
    try:
        url = f"http://{domain}"
        response = session.get(url, timeout=10, allow_redirects=True)
        
        print(f"URL Final: {response.url}")
        print(f"Status Code: {response.status_code}")
        print(f"Servidor: {response.headers.get('Server', 'Desconhecido')}")
        
        # Verificar tecnologias
        techs = []
        if 'X-Powered-By' in response.headers:
            techs.append(response.headers['X-Powered-By'])
        if 'X-AspNet-Version' in response.headers:
            techs.append("ASP.NET")
        
        if techs:
            print("Tecnologias Detectadas:")
            for tech in techs:
                print(f"  - {tech}")
    except Exception as e:
        print(f"Erro: {e}")

def check_tor_connection():
    """Verificar se a conexão Tor está funcionando"""
    session = get_tor_session()
    try:
        response = session.get("https://check.torproject.org/api/ip", timeout=10)
        data = response.json()
        if data.get('IsTor', False):
            print("\n[+] Conexão Tor ativa")
            print(f"IP Atual: {data.get('IP', 'Desconhecido')}")
            return True
        else:
            print("\n[!] AVISO: Não conectado via Tor!")
            return False
    except:
        print("\n[!] ERRO: Falha na conexão com a rede Tor")
        return False

def main():
    banner()
    
    # Verificar conexão Tor
    if not check_tor_connection():
        print("Configure o Tor antes de continuar")
        print("Instale com: sudo apt install tor")
        print("Inicie com: sudo systemctl start tor")
        return
    
    renew_tor_connection()
    session = get_tor_session()
    
    domain = input("\nDigite o domínio alvo: ").strip()
    if not domain:
        print("Domínio inválido")
        return
    
    # Extrair nome de domínio limpo
    parsed = urlparse(domain)
    domain_name = parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
    
    print(f"\nIniciando reconhecimento anônimo para: {domain_name}")
    
    # Executar verificações
    whois_lookup(domain_name, session)
    dns_lookup(domain_name)
    web_scan(domain_name, session)
    subdomain_enum(domain_name, session)
    leakix_lookup(domain_name, session)
    
    print("\n[+] Reconhecimento completo!")

if __name__ == "__main__":
    main()
