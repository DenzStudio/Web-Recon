import socket
import platform
from datetime import datetime
import requests
import whois
import sys
import time
from colorama import init, Fore, Style

# Init colorama
init(autoreset=True)

# Warna Logo (hijau & cyan)
logo = f"""{Fore.GREEN}
─────▄───▄
─▄█▄─█▀█▀█─▄█▄
▀▀████▄█▄████▀▀
─────▀█▀█▀

░██╗░░░░░░░██╗███████╗██████╗░  ██████╗░███████╗░█████╗░░█████╗░███╗░░██╗
░██║░░██╗░░██║██╔════╝██╔══██╗  ██╔══██╗██╔════╝██╔══██╗██╔══██╗████╗░██║
░╚██╗████╗██╔╝█████╗░░██████╦╝  ██████╔╝█████╗░░██║░░╚═╝██║░░██║██╔██╗██║
░░████╔═████║░██╔══╝░░██╔══██╗  ██╔══██╗██╔══╝░░██║░░██╗██║░░██║██║╚████║
░░╚██╔╝░╚██╔╝░███████╗██████╦╝  ██║░░██║███████╗╚█████╔╝╚█████╔╝██║░╚███║
░░░╚═╝░░░╚═╝░░╚══════╝╚═════╝░  ╚═╝░░╚═╝╚══════╝░╚════╝░░╚════╝░╚═╝░░╚══╝
{Fore.GREEN}
          Web Recon Tool by Denz coder
      version 1.0
      GitHub: DenzCoder
{Style.RESET_ALL}"""

common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389]

def loading_animation(text, duration=3):
    chars = ""
    for i in range(duration * 10):
        sys.stdout.write(f"\r{text} {chars[i % len(chars)]}")
        sys.stdout.flush()
        time.sleep(0.1)
    print("\r" + " " * (len(text) + 2), end="\r")  # Clear line

def get_ip(target):
    try:
        loading_animation(Fore.YELLOW + "[*] Resolving IP...")
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def get_dns(ip):
    try:
        loading_animation(Fore.YELLOW + "[*] Resolving DNS name...")
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Tidak diketahui"

def scan_ports(ip):
    print(Fore.YELLOW + "\n[+] Memindai port...")
    open_ports = []
    for port in common_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        result = s.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        s.close()
    return open_ports

def get_geoip(ip):
    try:
        loading_animation(Fore.YELLOW + "[*] Mendapatkan GeoIP info...")
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()
        return {
            "IP": ip,
            "Negara": data.get("country"),
            "Kota": data.get("city"),
            "ISP": data.get("org"),
            "Lokasi": data.get("loc")  # latitude,longitude
        }
    except:
        return {"IP": ip, "Info": "Gagal mendapatkan data GeoIP"}

def get_whois(domain):
    try:
        if not any(c.isalpha() for c in domain):
            return {"Domain": domain, "Info": "Bukan domain valid (mungkin IP langsung)"}
        loading_animation(Fore.YELLOW + "[*] Mengambil data WHOIS...")
        w = whois.whois(domain)
        return {
            "Domain": domain,
            "Registrar": w.registrar or "N/A",
            "Registrant": w.name or "Private/Unknown",
            "Email": w.emails or "Hidden",
            "Created": w.creation_date,
            "Expired": w.expiration_date
        }
    except Exception as e:
        return {"Domain": domain, "Info": f"Gagal mengambil WHOIS: {e}"}

def main():
    print(logo)
    target = input(Fore.CYAN + "Masukkan domain atau IP target: ").strip()
    print(Fore.MAGENTA + "\n[•] Waktu scan:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    ip = get_ip(target)
    if not ip:
        print(Fore.RED + "[-] IP tidak ditemukan. Periksa target dan koneksi internet.")
        return

    dns_name = get_dns(ip)
    os_name = platform.system()
    open_ports = scan_ports(ip)
    geoip_info = get_geoip(ip)
    whois_info = get_whois(target)

    print(Fore.GREEN + f"\n[✓] Target        : {target}")
    print(Fore.GREEN + f"[✓] IP Address    : {ip}")
    print(Fore.GREEN + f"[✓] DNS Name      : {dns_name}")
    print(Fore.GREEN + f"[✓] OS Lokal      : {os_name}")
    print(Fore.GREEN + f"[✓] Port Terbuka  : {', '.join(map(str, open_ports)) if open_ports else 'Tidak ditemukan'}")

    print(Fore.CYAN + "\n GEOIP Info:")
    for k, v in geoip_info.items():
        print(f"  {Fore.YELLOW}{k:10}: {Fore.WHITE}{v}")

    print(Fore.CYAN + "\n WHOIS Info:")
    for k, v in whois_info.items():
        print(f"  {Fore.YELLOW}{k:10}: {Fore.WHITE}{v}")

if __name__ == "__main__":
    main()
