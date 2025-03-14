import os
import socket
import struct
import time
import select
import sys

ICMP_ECHO_REQUEST = 8  
ICMP_TIME_EXCEEDED = 11  
MAX_HOPS = 64          
TIMEOUT = 2.0          
PACKETS_PER_HOP = 3    

def check_sum(source_string):
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0

    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xFFFFFFFF
        count = count + 2

    if count_to < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xFFFFFFFF

    sum = (sum >> 16) + (sum & 0xFFFF)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xFFFF
    answer = answer >> 8 | (answer << 8 & 0xFF00)
    return answer

def packet_create(pid, seq):
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, pid, seq)
    data = struct.pack("d", time.time())
    check_sum_value = check_sum(header + data)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(check_sum_value), pid, seq)
    return header + data

def traceroute(dest_name):
    try:
        dest_addr = socket.gethostbyname(dest_name)
    except socket.gaierror:
        print(f"Не удалось разрешить адрес: {dest_name}")
        return

    print(f"Трассировка маршрута до {dest_name} [{dest_addr}]")
    print()

    pid = os.getpid() & 0xFFFF
    ttl = 1
    seq = 1
    while ttl <= MAX_HOPS:
        print(f"{ttl:<3}", end="")

        hop_ip = None
        rtt_list = []

        for _ in range(PACKETS_PER_HOP):
            seq += 1
            try:
                recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                recv_socket.settimeout(TIMEOUT)
            except PermissionError:
                print("Для выполнения программы требуются права суперпользователя (sudo).")
                sys.exit(1)

            packet = packet_create(pid, seq)
            send_time = time.time()

            try:

                send_socket.sendto(packet, (dest_addr, 0))

                ready = select.select([recv_socket], [], [], TIMEOUT)
                if not ready[0]:
                    rtt_list.append("*")
                    continue

                recv_packet, addr = recv_socket.recvfrom(512)
                icmp_header = recv_packet[20:28]
                icmp_type, icmp_code, _, recv_pid, _ = struct.unpack("bbHHh", icmp_header)

                if icmp_type == ICMP_TIME_EXCEEDED or (icmp_type == 0 and recv_pid == pid):
                    rtt = (time.time() - send_time) * 1000
                    rtt_list.append(f"{rtt:.2f} ms")
                    hop_ip = addr[0]
                    if icmp_type == 0 and recv_pid == pid:
                        break
                else:
                    rtt_list.append("*")
            except socket.error:
                rtt_list.append("*")
            finally:
                send_socket.close()
                recv_socket.close()

        # Вывод IP и RTT
        for rtt in rtt_list:
            print(f" {rtt:<15}", end="")
        if hop_ip:
            print(f" {hop_ip:<20}", end="")
        else:
            print(" *", end="")



        print()
        ttl += 1

        if hop_ip == dest_addr:
            print("Трассировка завершена.")
            break

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Использование: {sys.argv[0]} <IP-адрес или доменное имя>")
        sys.exit(1)

    target = sys.argv[1]
    traceroute(target)
