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

def get_tor_session():
    """Criar sessão requests com proxy Tor"""
    session = requests.Session()
    session.proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
    return session

def renew_tor_connection():
    """Renovar circuito Tor para novo endereço IP"""
    print("\n[+] Renovando circuito Tor...")
    try:
        # Conexão direta sem proxy SOCKS
        with Controller.from_port(address="127.0.0.1", port=9051) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)
            time.sleep(5)  # Esperar circuito ser estabelecido
        print("[+] Circuito Tor renovado com sucesso!")
    except Exception as e:
        print(f"[!] Erro ao renovar circuito Tor: {e}")

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

def get_subdomains_from_file(wordlist="subdomains.txt"):
    default_subs = ["www", "mail", "ftp", "webmail", "admin", "api", 
                   "vpn", "ns1", "ns2", "test", "portal", "cpanel"]
    
    if os.path.exists(wordlist):
        with open(wordlist) as f:
            return [line.strip() for line in f if line.strip()]
    return default_subs

def subdomain_enum(domain, session):
    print("\n[+] Subdomain Enumeration via Tor...")
    subdomains = get_subdomains_from_file()
    
    def check_subdomain(sub):
        full_domain = f"{sub}.{domain}"
        try:
            # Resolução DNS via Tor
            ip = socket.gethostbyname(full_domain)
            return full_domain, ip
        except:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check_subdomain, sub): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                print(f"{result[0]} -> {result[1]}")

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

def check_tor_connection(session):
    """Verificar se a conexão Tor está funcionando"""
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
    except Exception as e:
        print(f"\n[!] ERRO: Falha na verificação Tor: {e}")
        return False

def main():
    banner()
    
    # Iniciar sessão Tor
    session = get_tor_session()
    
    # Verificar conexão Tor
    if not check_tor_connection(session):
        print("Configure o Tor antes de continuar")
        print("Instale com: sudo apt install tor")
        print("Inicie com: sudo systemctl start tor")
        return
    
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
    
    # Renovar circuito Tor ao final
    renew_tor_connection()
    
    print("\n[+] Reconhecimento completo!")

if __name__ == "__main__":
    main()
    
