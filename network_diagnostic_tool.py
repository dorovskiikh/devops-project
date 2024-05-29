import tkinter as tk
from tkinter import scrolledtext
import subprocess
from scapy.all import sr1, IP, ICMP, traceroute
import socket

class NetworkDiagnosticTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Diagnostic Tool")
        
        self.label = tk.Label(root)
        self.label.pack(pady=5)
        
        self.entry = tk.Entry(root, width=50)
        self.entry.pack(pady=5)
        
        self.ping_button = tk.Button(root, text="Ping", 
command=self.ping_host)
        self.ping_button.pack(pady=5)
        
        self.traceroute_button = tk.Button(root, text="Traceroute", 
command=self.traceroute_host)
        self.traceroute_button.pack(pady=5)
        
        self.dns_button = tk.Button(root, text="Check DNS", 
command=self.check_dns)
        self.dns_button.pack(pady=5)
        
        self.text_area = scrolledtext.ScrolledText(root, width=80, 
height=20)
        self.text_area.pack(pady=5)
    
    def ping_host(self):
        host = self.entry.get()
        if not host:
            self.text_area.insert(tk.END, "Please enter a valid IP or 
URL.\n")
            return
        
        try:
            response = sr1(IP(dst=host)/ICMP(), timeout=2, verbose=False)
            if response:
                self.text_area.insert(tk.END)
            else:
                self.text_area.insert(tk.END)
                self.text_area.insert(tk.END)
                self.text_area.insert(tk.END)
                self.text_area.insert(tk.END)
                self.text_area.insert(tk.END)
        except Exception as e:
            self.text_area.insert(tk.END)
            self.text_area.insert(tk.END)
            self.text_area.insert(tk.END)
            self.text_area.insert(tk.END)
            self.text_area.insert(tk.END)
    
    def traceroute_host(self):
        host = self.entry.get()
        if not host:
            self.text_area.insert(tk.END)
            return
        
        try:
            result, _ = traceroute(host, verbose=False)
            self.text_area.insert(tk.END)
            for snd, rcv in result:
                self.text_area.insert(tk.END, f"{snd.ttl} {rcv.src}\n")
        except Exception as e:
            self.text_area.insert(tk.END)
            self.text_area.insert(tk.END)
            self.text_area.insert(tk.END)
            self.text_area.insert(tk.END)
            self.text_area.insert(tk.END)
    
    def check_dns(self):
        host = self.entry.get()
        if not host:
            self.text_area.insert(tk.END)
            return
        
        try:
            ip = socket.gethostbyname(host)
            self.text_area.insert(tk.END)
        except Exception as e:
            self.text_area.insert(tk.END)
            self.text_area.insert(tk.END)
            self.text_area.insert(tk.END)
            self.text_area.insert(tk.END)
            self.text_area.insert(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkDiagnosticTool(root)
    root.mainloop()

