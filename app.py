from scapy.all import IP, TCP, sr1
import argparse

def banner():
    print(" _  __                 _        _  __                 _        _   _             ")
    print("| |/ /                | |      | |/ /                | |      | \ | |            ")
    print("| ' / _ __   ___   ___| | __   | ' / _ __   ___   ___| | __   |  \| | ___  ___   ")
    print("|  < | '_ \ / _ \ / __| |/ /   |  < | '_ \ / _ \ / __| |/ /   | . ` |/ _ \/ _ \  ")
    print("| . \| | | | (_) | (__|   < _  | . \| | | | (_) | (__|   < _  | |\  |  __/ (_) | ")
    print("|_|\_\_| |_|\___/ \___|_|\_( ) |_|\_\_| |_|\___/ \___|_|\_( ) |_| \_|\___|\___(_)")
    print("                           |/                             |/                     ")
    print('By: Arthur Ottoni -> https://github.com/arthurhydr/portknocking\n')

def make_knocking(ip, ports, flag):
    flag_mapping = {"syn": "S", "fin": "F"}
    if flag.lower() in flag_mapping:
        flag = flag_mapping[flag.lower()]

    for port in ports:
        packet = IP(dst=ip)/TCP(dport=port, flags=flag.upper())
        
        response = sr1(packet, timeout=1, verbose=0)
        if response:
            print(f'Port {port}: OPEN!')
        else:
            print(f'Port {port}: CLOSED, Knocking...')
def main():
    parser = argparse.ArgumentParser(description='Port Knocking Tool')
    parser.add_argument('-ip', '--host', help='Target host IP address', required=True)
    parser.add_argument('-p', '--ports', help='List of ports to knock, separated by commas', required=True)
    parser.add_argument('-f', '--flag', help='TCP flag to use for knocking (e.g., SYN, FIN)', default='S')
    args = parser.parse_args()

    host = args.host
    ports = [int(port) for port in args.ports.split(',')]
    flag = args.flag

    banner()
    make_knocking(host, ports, flag)

if __name__ == '__main__':
    main()
