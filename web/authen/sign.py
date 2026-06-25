#!/usr/bin/env python3
"""
HS256 (HMAC-SHA256) 通用暴力破解工具 (多进程版)
适用于任何使用HMAC-SHA256签名的场景
使用多进程绕过GIL限制，充分利用多核CPU
"""

import hmac
import hashlib
import sys
import os
import base64
from itertools import product, islice
from string import printable
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Manager, Value

# 常见弱密码本
COMMON_PASSWORDS = [
    "",
    "secret",
    "password",
    "jwt-secret",
    "jwtsecret",
    "my-secret",
    "mysecret",
    "secret-key",
    "secretkey",
    "key",
    "token",
    "auth",
    "authentication",
    "authorization",
    "admin",
    "root",
    "test",
    "demo",
    "api",
    "apikey",
    "api-key",
    "api-secret",
    "apisecret",
    "sign",
    "signature",
    "hash",
    "123456",
    "12345678",
    "password123",
    "admin123",
    "secret123",
    "jwt",
    "json-web-token",
    "jsonwebtoken",
    "webtoken",
    "web-token",
    "auth-token",
    "auth-token-secret",
    "authsecret",
    "default",
    "config",
    "configuration",
    "private",
    "public",
    "security",
    "secure",
    "login",
    "session",
    "access",
    "tokenize",
    "signing",
    "hmac",
    "sha256",
    "hs256",
    "HS256",
    "my-key",
    "mykey",
    "your-secret",
    "yoursecret",
    "shared-secret",
    "sharedsecret",
    "shared-key",
    "sharedkey",
    "secret0",
    "secret1",
    "secret2",
    "my-secret-key",
    "mysecretkey",
    "jwt-secret-key",
    "jwtsecretkey",
    "secret-key-123",
    "secretkey123",
    "test-secret",
    "testsecret",
    "demo-secret",
    "demosecret",
    "dev-secret",
    "devsecret",
    "prod-secret",
    "prodsecret",
    "staging-secret",
    "stagingsecret",
    "app-secret",
    "appsecret",
    "application-secret",
    "applicationsecret",
    "server-secret",
    "serversecret",
    "client-secret",
    "clientsecret",
    "user-secret",
    "usersecret",
    "auth0",
    "auth1",
    "auth2",
    "token0",
    "token1",
    "token2",
    "key0",
    "key1",
    "key2",
    "signing-key",
    "signingkey",
    "signing-secret",
    "signingsecret",
    "verify-key",
    "verifykey",
    "verify-secret",
    "verifysecret",
    "0123456789abcdef",
    "abcdef0123456789",
    "0123456789ABCDEF",
    "ABCDEF0123456789",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789",
    "abcdefgh",
    "abcd1234",
    "1234abcd",
    "00000000",
    "11111111",
    "22222222",
    "33333333",
    "44444444",
    "55555555",
    "66666666",
    "77777777",
    "88888888",
    "99999999",
    "aaaaaaaa",
    "bbbbbbbb",
    "cccccccc",
    "dddddddd",
    "eeeeeeee",
    "ffffffff",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "00000000000000000000000000000000",
    "11111111111111111111111111111111",
    "flag",
    "FLAG",
    "ctf",
    "CTF",
    "challenge",
    "payload",
    "data",
    "message",
    "salt",
    "pepper",
]


def compute_hmac_sha256(message, secret):
    """计算HMAC-SHA256"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    if isinstance(secret, str):
        secret = secret.encode('utf-8')

    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def compute_hmac_sha256_raw(message, secret):
    """计算HMAC-SHA256 (返回原始字节)"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    if isinstance(secret, str):
        secret = secret.encode('utf-8')

    return hmac.new(secret, message, hashlib.sha256).digest()


def decode_signature(signature):
    """自动检测并解码签名格式（hex/base64/原始字节）"""
    if isinstance(signature, bytes):
        return signature

    # 尝试hex解码
    try:
        sig =  bytes.fromhex(signature)
        print("[*] 识别到hex签名")
        return sig
    except ValueError:
        pass

    # 尝试base64解码
    try:
        # 处理URL安全的base64
        sig = signature.replace('-', '+').replace('_', '/')
        # 添加padding
        padding = len(sig) % 4
        if padding:
            sig += '=' * (4 - padding)
        sig = base64.b64decode(sig)
        print("[*] 识别到base64签名")
        return sig
    except Exception:
        pass

    # 作为UTF-8字符串返回
    try:
        sig = signature.encode('utf-8')
        print("[*] 未识别签名格式，回退到utf-8编码")
        return sig
    except Exception as e:
        print(f"[!] utf-8编码失败！{e}")
        sig = signature.encode('utf-8', errors='ignore')
        return sig
        


def try_verify(message, target_signature, secret, raw=False):
    """尝试用给定密钥验证HMAC-SHA256签名"""
    if raw:
        computed = compute_hmac_sha256_raw(message, secret)
        # 解码目标签名
        decoded_sig = decode_signature(target_signature)
        return computed == decoded_sig
    else:
        computed = compute_hmac_sha256(message, secret)
        return computed == target_signature.lower()


def try_password(args):
    """尝试单个密码（用于多进程）"""
    message, target_signature, secret, raw = args

    if try_verify(message, target_signature, secret, raw):
        return secret
    return None


def try_password_batch(args):
    """尝试一批密码（用于多进程，减少进程间通信开销）"""
    message, target_signature, secrets_batch, raw = args

    for secret in secrets_batch:
        if try_verify(message, target_signature, secret, raw):
            return secret
    return None


def brute_force_with_wordlist(message, target_signature, wordlist, raw=False, workers=8):
    """使用密码本进行暴力破解（多进程）"""
    print(f"[*] 尝试密码本中的 {len(wordlist)} 个密码...")
    print(f"[*] 使用 {workers} 个进程")

    # 预先解码签名
    decoded_target = decode_signature(target_signature)
    sig_format = "hex" if len(decoded_target) * 2 == len(target_signature.strip()) else "base64"
    print(f"[*] 检测到签名格式: {sig_format}")

    # 将密码本分成批次，每批1000个密码
    batch_size = 1000
    batches = []

    for i in range(0, len(wordlist), batch_size):
        batch = wordlist[i:i + batch_size]
        # 使用解码后的签名
        batches.append((message, decoded_target, batch, True))

    print(f"[*] 分成 {len(batches)} 个批次")

    # 使用进程池
    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(try_password_batch, batch): i for i, batch in enumerate(batches)}

        completed = 0
        for future in as_completed(futures):
            completed += 1

            if completed % max(1, len(batches) // 20) == 0:
                print(f"[*] 已完成 {completed}/{len(batches)} 个批次...", end="\r")

            result = future.result()
            if result is not None:
                print(f"\n[+] 找到密钥: '{result}'")
                computed_sig = compute_hmac_sha256_raw(message, result)
                print(f"[+] 计算出的签名 (hex): {computed_sig.hex()}")
                print(f"[+] 计算出的签名 (base64): {base64.b64encode(computed_sig).decode('ascii')}")

                # 强制终止
                executor.shutdown(wait=False, cancel_futures=True)
                return result

    print()
    return None


def batch_generator(charset, length, batch_size):
    """生成器：按批次生成密码组合"""
    batch = []
    for attempt_tuple in product(charset, repeat=length):
        secret = "".join(attempt_tuple)
        batch.append(secret)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def brute_force_enumerate(message, target_signature, charset, max_length, raw=False, workers=8):
    """枚举暴力破解（多进程）"""
    print(f"[*] 开始枚举破解 (长度: 1-{max_length}, 字符集大小: {len(charset)})")
    print(f"[*] 使用 {workers} 个进程")
    print("[!] 警告: 枚举破解时间可能非常长!")

    # 预先解码签名
    decoded_target = decode_signature(target_signature)

    total_combinations = sum(len(charset) ** length for length in range(1, max_length + 1))
    print(f"[*] 总组合数: {total_combinations:,}")

    batch_size = 50000  # 每批处理的密码数量
    count = 0

    for length in range(1, max_length + 1):
        print(f"[*] 正在尝试长度为 {length} 的密码...")

        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = []

            # 提交所有批次任务
            for batch in batch_generator(charset, length, batch_size):
                args = (message, decoded_target, batch, True)  # 始终使用raw模式比较字节
                future = executor.submit(try_password_batch, args)
                futures.append(future)
                count += len(batch)

                # 限制同时进行的任务数，避免内存爆炸
                if len(futures) >= workers * 2:
                    # 等待部分任务完成
                    for future in as_completed(futures):
                        result = future.result()
                        if result is not None:
                            print(f"\n[+] 找到密钥: '{result}'")
                            computed_sig = compute_hmac_sha256_raw(message, result)
                            print(f"[+] 计算出的签名 (hex): {computed_sig.hex()}")
                            print(f"[+] 计算出的签名 (base64): {base64.b64encode(computed_sig).decode('ascii')}")

                            executor.shutdown(wait=False, cancel_futures=True)
                            return result

                    futures = []

                if count % 100000 == 0:
                    print(f"[*] 已生成 {count:,}/{total_combinations:,} 个密码...", end="\r")

            # 等待剩余任务完成
            if futures:
                for future in as_completed(futures):
                    result = future.result()
                    if result is not None:
                        print(f"\n[+] 找到密钥: '{result}'")
                        computed_sig = compute_hmac_sha256_raw(message, result)
                        print(f"[+] 计算出的签名 (hex): {computed_sig.hex()}")
                        print(f"[+] 计算出的签名 (base64): {base64.b64encode(computed_sig).decode('ascii')}")

                        executor.shutdown(wait=False, cancel_futures=True)
                        return result

    print()
    return None


def main():
    if len(sys.argv) < 3:
        print("用法: python sign.py <message> <signature> [options]")
        print()
        print("参数:")
        print("  message           要签名的消息内容")
        print("  signature         目标HMAC-SHA256签名 (hex格式)")
        print()
        print("选项:")
        print("  -w, --wordlist    使用密码本文件")
        print("  -l, --length      枚举最大长度 (默认: 3)")
        print("  -p, --processes   进程数 (默认: CPU核心数)")
        print("  -c, --charset     枚举字符集 (默认: 字母+数字)")
        print("  -r, --raw         已弃用（自动检测签名格式）")
        print()
        print("示例:")
        print("  # 使用hex格式签名")
        print("  python sign.py 'message' 'a1b2c3d4e5f6...'")
        print()
        print("  # 使用base64格式签名（自动检测）")
        print("  python sign.py 'message' 'YWJjZGVmZ2hpams='")
        print()
        print("  # 使用自定义密码本文件 (16个进程)")
        print("  python sign.py 'message' 'signature' -w passwords.txt -p 16")
        print()
        print("  # 枚举长度1-3的密码 (32个进程)")
        print("  python sign.py 'message' 'signature' -l 3 -p 32")
        print()
        print("  # 指定字符集枚举")
        print("  python sign.py 'message' 'signature' -l 2 -c 'abcdef0123456789'")
        print()
        print("签名格式说明:")
        print("  - hex字符串:       'a1b2c3d4e5f6...'")
        print("  - base64字符串:    'YWJjZGVmZ2hpams=' (自动检测)")
        print("  - URL安全base64:   'YWJjZGVmZ2hpams' (自动检测)")
        print("  程序会自动检测并解码签名格式")
        print()
        print("注意: 使用多进程绕过GIL限制，充分利用多核CPU")
        sys.exit(1)

    message = sys.argv[1]
    target_signature = sys.argv[2]

    # 解析参数
    wordlist_file = None
    max_length = 3
    workers = os.cpu_count() or 4
    raw = False
    charset = printable[:62]  # 字母+数字

    i = 3
    while i < len(sys.argv):
        if sys.argv[i] in ['-w', '--wordlist'] and i + 1 < len(sys.argv):
            wordlist_file = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] in ['-l', '--length'] and i + 1 < len(sys.argv):
            max_length = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] in ['-p', '--processes'] and i + 1 < len(sys.argv):
            workers = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] in ['-t', '--threads'] and i + 1 < len(sys.argv):
            # 兼容旧参数名
            workers = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] in ['-r', '--raw']:
            raw = True
            i += 1
        elif sys.argv[i] in ['-c', '--charset'] and i + 1 < len(sys.argv):
            charset = sys.argv[i + 1]
            i += 2
        else:
            i += 1

    print("=" * 60)
    print("HS256 (HMAC-SHA256) 通用暴力破解工具 (多进程版)")
    print("=" * 60)
    print(f"[*] 消息: {message}")
    print(f"[*] 目标签名: {target_signature[:50] if len(target_signature) > 50 else target_signature}...")
    print(f"[*] 进程数: {workers}")
    print(f"[*] 枚举最大长度: {max_length}")
    print(f"[*] 字符集大小: {len(charset)}")
    print(f"[*] CPU核心数: {os.cpu_count() or '未知'}")
    print()

    secret = None

    # 优先级1: 使用密码本文件
    if wordlist_file:
        print("[*] 使用密码本文件模式")
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            print(f"[*] 从文件加载了 {len(passwords)} 个密码")
            secret = brute_force_with_wordlist(message, target_signature, passwords, raw, workers)
        except FileNotFoundError:
            print(f"[-] 文件未找到: {wordlist_file}")
            sys.exit(1)

    # 优先级2: 使用内置弱密码本
    if secret is None:
        secret = brute_force_with_wordlist(message, target_signature, COMMON_PASSWORDS, raw, workers)

    # 优先级3: 枚举破解
    if secret is None:
        print("\n[-] 弱密码本未找到匹配密钥")
        print("[*] 开始枚举破解...")
        secret = brute_force_enumerate(message, target_signature, charset, max_length, raw, workers)

    if secret is None:
        print("\n[-] 未找到有效密钥")
        print("[*] 建议:")
        print("    1. 增加 -l 参数 (枚举长度)")
        print("    2. 使用 -w 指定密码本文件")
        print("    3. 使用 -c 调整字符集")
        print("    4. 增加 -p 参数 (进程数)")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("[+] 破解成功!")
    print(f"[+] 密钥: {secret}")
    print("=" * 60)


if __name__ == "__main__":
    # Windows多进程必须放在 if __name__ == "__main__" 下
    main()
