import os
import socket
import struct
import time
import re

def checksum(data):
    """Bu fonksiyon, ICMP paketlerinin dogrulugunu kontrol etmek icin checksum hesaplamasi yapar.
    ICMP basliklarinin gecerligini saglar."""
    if len(data) % 2:
        data += b'\0'
    res = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    res = (res >> 16) + (res & 0xFFFF)
    res += res >> 16
    return ~res & 0xFFFF

def create_icmp_packet(id, seq):
    """ICMP Echo Request paketi olusturur.
    Basliklari ve payload'u birlestirir ve checksum hesaplar."""
    header = struct.pack('!BBHHH', 8, 0, 0, id, seq)  # Type, Code, Checksum, ID, Sequence
    payload = b'PingTest'  # Gonderilecek veri yuklemi
    checksum_val = checksum(header + payload)
    header = struct.pack('!BBHHH', 8, 0, checksum_val, id, seq)
    return header + payload

def is_valid_ip(ip):
    """Verilen IP adresinin formatinin gecerli olup olmadigini kontrol eder.
    Sadece IPv4 formatlari kabul edilir."""
    pattern = re.compile(r"^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$")
    return pattern.match(ip) is not None

def log_message(message):
    """Belirtilen mesaji log dosyasina kaydeder.
    Her mesaj zaman damgasi ile birlikte kaydedilir."""
    with open("ping_log.txt", "a") as log_file:
        log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

def system_traceroute(destination, max_hops=30):
    """Traceroute islemini sistem komutlari ile gerceklestirir.
    Hedefe kadar tum router'lari listeler ve sureyi olcer."""
    print(f"{destination} icin traceroute calisiyor (maksimum atlama: {max_hops})...")
    log_message(f"{destination} icin traceroute baslatiliyor")

    # Traceroute baslangic zamani
    start_time = time.time()

    try:
        # Traceroute komutunu calistir
        os.system(f"tracert -h {max_hops} {destination}")

        # Traceroute bitis zamani
        end_time = time.time()
        duration = end_time - start_time

        print(f"\n{destination} icin traceroute tamamlandi. Sure: {duration:.2f} saniye.")
        log_message(f"{destination} icin traceroute tamamlandi. Sure: {duration:.2f} saniye.")

    except Exception as e:
        error_message = f"Beklenmeyen bir hata olustu: {e}"
        print(error_message)
        log_message(error_message)

def send_ping(destination, timeout=1, count=4):
    """Belirtilen hedefe ICMP Echo Request paketleri gonderir ve yanitlari toplar.
    Zaman asimi ve istatistik hesaplama islemlerini icerir."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            sock.settimeout(timeout)

            try:
                if not is_valid_ip(destination):
                    dest_addr = socket.gethostbyname(destination)
                else:
                    dest_addr = destination
            except socket.gaierror:
                error_message = f"Hata: '{destination}' adresi cozumlenemedi. Lutfen gecerli bir hostname veya IP adresi girin."
                print(error_message)
                log_message(error_message)
                return

            log_message(f"{dest_addr} icin {count} paket ile ping baslatiliyor...")
            print(f"{dest_addr} icin {count} paket ile ping baslatiliyor...")

            packet_id = os.getpid() & 0xFFFF
            times = []
            sent_count = 0
            received_count = 0

            for seq in range(1, count + 1):
                packet = create_icmp_packet(packet_id, seq)

                try:
                    start_time = time.time()
                    sock.sendto(packet, (dest_addr, 1))
                    sent_count += 1
                    log_message(f"ID={packet_id} ve Seq={seq} ile {dest_addr} icin ICMP paketi gonderildi.")

                    reply, addr = sock.recvfrom(1024)
                    end_time = time.time()

                    ip_header = reply[:20]
                    icmp_header = reply[20:28]

                    _, _, _, recv_id, recv_seq = struct.unpack('!BBHHH', icmp_header)

                    if recv_id == packet_id and recv_seq == seq:
                        rtt = (end_time - start_time) * 1000
                        times.append(rtt)
                        received_count += 1
                        success_message = f"{addr[0]} adresinden yanit: sure={rtt:.2f} ms"
                        print(success_message)
                        log_message(success_message)
                    else:
                        warning_message = "Uyari: Alinan paket, gonderilen ICMP Echo Request ile eslesmiyor."
                        print(warning_message)
                        log_message(warning_message)

                except socket.timeout:
                    timeout_message = "Hata: Istek zaman asimina ugradi. Hedef ulasilamaz olabilir."
                    print(timeout_message)
                    log_message(timeout_message)

                time.sleep(1)  # Ping istekleri arasinda gecikme

            stats = calculate_statistics(times)
            loss_percentage = ((sent_count - received_count) / sent_count) * 100
            print(f"\nPaketler: Gonderilen = {sent_count}, Alinan = {received_count}, Kaybolan = {sent_count - received_count} ({loss_percentage:.2f}% kayip)")
            log_message(f"Paket kaybi: Gonderilen={sent_count}, Alinan={received_count}, Kaybolan={sent_count - received_count} ({loss_percentage:.2f}% kayip)")

    except PermissionError:
        permission_message = "Hata: Bu scripti calistirmak icin kok yetkilerine ihtiyaciniz var."
        print(permission_message)
        log_message(permission_message)
    except Exception as e:
        error_message = f"Beklenmeyen bir hata olustu: {e}"
        print(error_message)
        log_message(error_message)

def calculate_statistics(times):
    """Yanıt süreleri icin istatistik hesaplar (minimum, maksimum, ortalama)."""
    if not times:
        return None
    return {
        'min': min(times),
        'max': max(times),
        'avg': sum(times) / len(times),
        'count': len(times)
    }

def print_statistics(stats):
    """Ping istatistiklerini kullanici dostu bir formatta yazdirir."""
    if stats:
        print(f"\n--- Ping Istatistikleri ---")
        print(f"Paketler: Gonderilen = {stats['count']}, Alinan = {stats['count']}, Kaybolan = 0")
        print(f"Yaklasik gidiş-donus suresi milisaniye cinsinden:")
        print(f"    Minimum = {stats['min']:.2f}ms, Maksimum = {stats['max']:.2f}ms, Ortalama = {stats['avg']:.2f}ms")
    else:
        print("Hicbir paket gonderilmedi.")

if __name__ == "__main__":
    while True:
        print("Secenekler:")
        print("1. Ping")
        print("2. Traceroute")
        choice = input("Bir secenek girin (1/2): ")

        if choice == "1":
            target = input("Hedef hostname veya IP adresini girin: ")
            if is_valid_ip(target) or target:
                send_ping(target)
            else:
                print("Hata: Gecerli bir IP adresi veya hostname girin.")
        elif choice == "2":
            target = input("Hedef hostname veya IP adresini girin: ")
            if is_valid_ip(target) or target:
                system_traceroute(target)
            else:
                print("Hata: Gecerli bir IP adresi veya hostname girin.")
        else:
            print("Hata: Gecerli bir secenek girin.")

        while True:
            continue_choice = input("Isleme devam etmek istiyor musunuz? (e/h): ").lower()
            if continue_choice == 'e':
                break  # Donguye devam eder
            elif continue_choice == 'h':
                print("Programdan cikiliyor.")
                exit()  # Programi tamamen sonlandirir
            else:
                print("Gecersiz giris. Lutfen 'e' veya 'h' girin.")
