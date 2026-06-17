#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import platform
import select
import socket
import struct
import sys
import time
import traceback


def calculate_checksum(data):
    checksum = 0
    if len(data) % 2 == 1:
        data += b'\x00'
    for i in range(0, len(data), 2):
        checksum += (data[i] << 8) + data[i + 1]
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    return checksum


def build_icmp_packet(seq, ident=12345):
    packet = struct.pack('!BBHHH', 8, 0, 0, ident, seq)
    checksum = calculate_checksum(packet)
    return struct.pack('!BBHHH', 8, 0, checksum, ident, seq)


def resolve_target(target):
    print(f'[resolve] input={target}')
    addrinfos = socket.getaddrinfo(
        target, None, socket.AF_UNSPEC, socket.SOCK_DGRAM
    )
    for index, info in enumerate(addrinfos, start=1):
        family, socktype, proto, canonname, sockaddr = info
        print(
            '[resolve] #%s family=%s socktype=%s proto=%s canonname=%r sockaddr=%r'
            % (index, family, socktype, proto, canonname, sockaddr)
        )

    family, _, _, _, sockaddr = addrinfos[0]
    if family != socket.AF_INET:
        raise RuntimeError(f'Only IPv4 is supported by this debug script, got family={family}')
    resolved_ip = sockaddr[0]
    print(f'[resolve] selected_ipv4={resolved_ip}')
    return resolved_ip


def recv_with_timeout(sock_fd, timeout):
    ready, _, _ = select.select([sock_fd], [], [], timeout)
    if not ready:
        raise TimeoutError(f'recv timeout after {timeout}s')
    return sock_fd.recvfrom(1024)


def debug_traceroute(target, max_hops, timeout, pause):
    print(f'[target] {target}')
    resolved_ip = resolve_target(target)

    print("[step] socket.getprotobyname('icmp')")
    icmp_proto = socket.getprotobyname('icmp')
    print(f'[ok] icmp_proto={icmp_proto}')

    print('[step] socket(AF_INET, SOCK_RAW, icmp_proto)')
    sock_fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_proto)
    print(f'[ok] raw_socket_fd={sock_fd.fileno()}')

    try:
        for ttl in range(1, max_hops + 1):
            print(f'\n[ttl={ttl}]')

            print(f'[step] setsockopt(IP_TTL={ttl})')
            sock_fd.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            print('[ok] setsockopt')

            print(f'[step] settimeout({timeout})')
            sock_fd.settimeout(timeout)
            print('[ok] settimeout')

            packet = build_icmp_packet(ttl)
            print(f'[step] sendto({resolved_ip}, 0), bytes={len(packet)}')
            start_time = time.time()
            sent_bytes = sock_fd.sendto(packet, (resolved_ip, 0))
            print(f'[ok] sent_bytes={sent_bytes}')

            if pause > 0:
                time.sleep(pause)

            print(f'[step] recvfrom(timeout={timeout})')
            recv_packet, addr = recv_with_timeout(sock_fd, timeout)
            elapsed_ms = (time.time() - start_time) * 1000
            dest_ip = addr[0]
            print(
                f'[ok] addr={addr!r} bytes={len(recv_packet)} elapsed_ms={elapsed_ms:.3f}'
            )
            print(f'[hop] {ttl} {dest_ip} ({dest_ip}) {elapsed_ms:.3f} ms')

            if dest_ip == resolved_ip:
                print('[done] destination reached')
                return 0

        print('[done] max hops reached')
        return 0
    finally:
        sock_fd.close()
        print('[cleanup] socket closed')


def main():
    parser = argparse.ArgumentParser(
        description='Debug raw-socket traceroute step by step'
    )
    parser.add_argument('target', help='IP or domain to trace')
    parser.add_argument('--max-hops', type=int, default=5, help='Max hops to probe')
    parser.add_argument('--timeout', type=float, default=3.0, help='Recv timeout in seconds')
    parser.add_argument(
        '--pause',
        type=float,
        default=0.01,
        help='Pause between send and recv to mimic current implementation',
    )
    parser.add_argument(
        '--traceback',
        action='store_true',
        help='Print full traceback on failure',
    )
    args = parser.parse_args()

    print(f'[env] python={sys.version.split()[0]}')
    print(f'[env] platform={platform.platform()}')
    print(f'[env] pid={os.getpid()} uid={os.getuid()} euid={os.geteuid()}')
    print(f'[env] argv={sys.argv!r}')

    try:
        return debug_traceroute(
            target=args.target,
            max_hops=args.max_hops,
            timeout=args.timeout,
            pause=args.pause,
        )
    except Exception as exc:
        print(f'[error] {type(exc).__name__}: {exc}')
        if args.traceback:
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
