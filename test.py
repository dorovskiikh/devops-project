import argparse
import subprocess
from scapy.all import sr1, IP, ICMP, traceroute
import socket

def ping_host(host):
    try:
        response = sr1(IP(dst=host)/ICMP(), timeout=2, verbose=False)
        if response:
            print(f"Хост {host} доступен.")
        else:
            print(f"Хост {host} не доступен.")
            print("Возможные варианты решения:")
            print("1. Проверьте, включено ли устройство и подключено ли оно к сети.")
            print("2. Убедитесь, что IP-адрес или URL-адрес верны.")
            print("3. Убедитесь, что ваш маршрутизатор и модем работают правильно.")
    except Exception as e:
        print(f"Ошибка: {e}")
        print("Возможные варианты решения:")
        print("1. Проверьте подключение к Интернету.")
        print("2. Убедитесь, что ваш брандмауэр или антивирусное программное обеспечение не блокирует соединение.")
        print("3. Перезагрузите маршрутизатор и модем.")

def traceroute_host(host):
    try:
        result, _ = traceroute(host, verbose=False)
        print(f"Трассировка до {host}:")
        for snd, rcv in result:
            print(f"{snd.ttl} {rcv.src}")
    except Exception as e:
        print(f"Ошибка: {e}")
        print("Возможные варианты решения:")
        print("1. Проверьте подключение к Интернету.")
        print("2. Убедитесь, что ваш брандмауэр или антивирусное программное обеспечение не блокирует соединение.")
        print("3. Перезагрузите маршрутизатор и модем.")

def check_dns(host):
    try:
        ip = socket.gethostbyname(host)
        print(f"IP-адрес {host} – {ip}.")
    except Exception as e:
        print(f"Ошибка: {e}")
        print("Возможные варианты решения:")
        print("1. Убедитесь, что URL-адрес верен.")
        print("2. Проверьте настройки DNS.")
        print("3. Попробуйте использовать другой DNS-сервер.")

def main():
    parser = argparse.ArgumentParser(description="Network Diagnostic Tool")
    parser.add_argument("command", choices=["ping", "traceroute", "dns"], help="Команда для выполнения: ping, traceroute, dns")
    parser.add_argument("host", help="IP или URL для диагностики")

    args = parser.parse_args()

    if args.command == "ping":
        ping_host(args.host)
    elif args.command == "traceroute":
        traceroute_host(args.host)
    elif args.command == "dns":
        check_dns(args.host)

if __name__ == "__main__":
    main()
