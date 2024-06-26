import tkinter as tk
from tkinter import scrolledtext
import subprocess
from scapy.all import sr1, IP, ICMP, traceroute
import socket

class NetworkDiagnosticTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Diagnostic Tool")
        
        self.label = tk.Label(root, text="Введите IP или URL:")
        self.label.pack(pady=5)
        
        self.entry = tk.Entry(root, width=50)
        self.entry.pack(pady=5)
        
        self.ping_button = tk.Button(root, text="Пинг", 
command=self.ping_host)
        self.ping_button.pack(pady=5)
        
        self.traceroute_button = tk.Button(root, text="Трассировка", 
command=self.traceroute_host)
        self.traceroute_button.pack(pady=5)
        
        self.dns_button = tk.Button(root, text="Проверка DNS", 
command=self.check_dns)
        self.dns_button.pack(pady=5)
        
        self.text_area = scrolledtext.ScrolledText(root, width=80, 
height=20)
        self.text_area.pack(pady=5)
    
    def ping_host(self):
        host = self.entry.get()
        if not host:
            self.text_area.insert(tk.END, "Пожалуйста, введите корректный 
IP или URL.\n")
            return
        
        try:
            response = sr1(IP(dst=host)/ICMP(), timeout=2, verbose=False)
            if response:
                self.text_area.insert(tk.END, f"Хост {host} доступен.\n")
            else:
                self.text_area.insert(tk.END, f"Хост {host} не 
доступен.\n")
                self.text_area.insert(tk.END, "Возможные варианты 
решения:\n")
                self.text_area.insert(tk.END, "1. Проверьте, включено ли 
устройство и подключено ли оно к сети.\n")
                self.text_area.insert(tk.END, "2. Убедитесь, что IP-адрес 
или URL-адрес верны.\n")
                self.text_area.insert(tk.END, "3. Убедитесь, что ваш 
маршрутизатор и модем работают правильно..\n")
        except Exception as e:
            self.text_area.insert(tk.END, f"Error: {e}\n")
            self.text_area.insert(tk.END, "Возможные варианты решения:\n")
            self.text_area.insert(tk.END, "1. Проверьте подключение к 
Интернету.\n")
            self.text_area.insert(tk.END, "2. Убедитесь, что ваш 
брандмауэр или антивирусное программное обеспечение не блокирует 
соединение.\n")
            self.text_area.insert(tk.END, "3. Перезагрузите маршрутизатор 
и модем.\n")
    
    def traceroute_host(self):
        host = self.entry.get()
        if not host:
            self.text_area.insert(tk.END, "Пожалуйста, введите корректный 
IP или URL.\n")
            return
        
        try:
            result, _ = traceroute(host, verbose=False)
            self.text_area.insert(tk.END, f"Трассировка до {host}:\n")
            for snd, rcv in result:
                self.text_area.insert(tk.END, f"{snd.ttl} {rcv.src}\n")
        except Exception as e:
            self.text_area.insert(tk.END, f"Ошибка: {e}\n")
            self.text_area.insert(tk.END, "Возможные варианты решения:\n")
            self.text_area.insert(tk.END, "1. Проверьте подключение к 
Интернету.\n")
            self.text_area.insert(tk.END, "2. Убедитесь, что ваш 
брандмауэр или антивирусное программное обеспечение не блокирует 
соединение.\n")
            self.text_area.insert(tk.END, "3. Перезагрузите маршрутизатор 
и модем.\n")
    
    def check_dns(self):
        host = self.entry.get()
        if not host:
            self.text_area.insert(tk.END, "Пожалуйста, введите корректный 
URL.\n")
            return
        
        try:
            ip = socket.gethostbyname(host)
            self.text_area.insert(tk.END, f"IP-адрес {host} – {ip}.\n")
        except Exception as e:
            self.text_area.insert(tk.END, f"Ошибка: {e}\n")
            self.text_area.insert(tk.END, "Возможные варианты решения:\n")
            self.text_area.insert(tk.END, "1. Убедитесь, что URL-адрес 
верен.\n")
            self.text_area.insert(tk.END, "2. Проверьте настройки DNS.\n")
            self.text_area.insert(tk.END, "3. Попробуйте использовать 
другой DNS-сервер.\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkDiagnosticTool(root)
    root.mainloop()

