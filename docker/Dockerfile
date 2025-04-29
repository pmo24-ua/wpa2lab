FROM kalilinux/kali-rolling
RUN apt update && apt install -y \\
    hostapd dnsmasq hcxdumptool hcxpcaptool aircrack-ng hashcat python3-pip
WORKDIR /root/wpa2lab
COPY . .
RUN pip3 install typer[all] pyyaml
ENTRYPOINT ["python3","scripts/wpa2lab.py"]
