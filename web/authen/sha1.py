import hashlib
import multiprocessing
import string
import argparse
from pathlib import Path
from typing import Optional


# 全局变量，用于多进程共享
_target_hash = None
_salt = None
_found = False


def sha1_encrypt(message):
    sha1 = hashlib.sha1()
    sha1.update(message.encode('utf-8'))
    return sha1.hexdigest()


def sha1_hash(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest()


def check_password(password: str) -> bool:
    global _found
    if _found:
        return False

    text = password + (_salt if _salt else '')
    if sha1_hash(text) == _target_hash:
        _found = True
        return True
    return False


def wordlist_worker(passwords: list) -> Optional[str]:
    for password in passwords:
        password = password.strip()
        if check_password(password):
            return password
    return None


def brute_worker(args: tuple) -> Optional[str]:
    charset, length = args

    def generate(current, remaining):
        global _found
        if _found:
            return
        if remaining == 0:
            if check_password(''.join(current)):
                return True
            return
        for char in charset:
            if _found:
                return
            current.append(char)
            generate(current, remaining - 1)
            current.pop()

    generate([], length)
    return None


class SHA1Cracker:
    def __init__(self, target_hash: str, wordlist: Optional[str] = None, salt: Optional[str] = None):
        self.target_hash = target_hash.lower()
        self.wordlist = wordlist
        self.salt = salt

    def crack_with_wordlist(self) -> Optional[str]:
        global _target_hash, _salt, _found
        _target_hash = self.target_hash
        _salt = self.salt
        _found = False

        if not self.wordlist or not Path(self.wordlist).exists():
            return None

        print(f"[*] 使用密码表: {self.wordlist}")

        with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]

        if not passwords:
            return None

        print(f"[*] 加载了 {len(passwords)} 个密码")

        num_processes = multiprocessing.cpu_count()
        chunk_size = len(passwords) // num_processes + 1

        chunks = []
        for i in range(0, len(passwords), chunk_size):
            chunks.append(passwords[i:i + chunk_size])

        with multiprocessing.Pool(processes=num_processes) as pool:
            results = pool.imap_unordered(wordlist_worker, chunks)
            for result in results:
                if result:
                    return result

        return None

    def crack_with_bruteforce(self, charset: str = None,
                             min_length: int = 1, max_length: int = 6) -> Optional[str]:
        global _target_hash, _salt, _found
        _target_hash = self.target_hash
        _salt = self.salt
        _found = False

        if charset is None:
            charset = string.ascii_lowercase + string.digits

        print(f"[*] 开始枚举爆破")
        print(f"[*] 字符集: {charset}")
        print(f"[*] 长度范围: {min_length}-{max_length}")

        num_processes = multiprocessing.cpu_count()

        for length in range(min_length, max_length + 1):
            if _found:
                break

            total = len(charset) ** length
            print(f"[*] 尝试长度 {length} (共 {total:,} 种组合)")

            args_list = [(charset, length)] * num_processes

            with multiprocessing.Pool(processes=num_processes) as pool:
                pool.map(brute_worker, args_list)

            if _found:
                break

        return None

    def crack(self, charset: str = None,
             min_length: int = 1, max_length: int = 6) -> Optional[str]:
        print(f"[*] 目标哈希: {self.target_hash}")
        if self.salt:
            print(f"[*] 盐值: {self.salt}")
        print("=" * 50)

        if self.wordlist:
            result = self.crack_with_wordlist()
            if result:
                print("=" * 50)
                print(f"[+] 找到密码: {result}")
                return result
            print("[-] 密码表中未找到")

        result = self.crack_with_bruteforce(charset, min_length, max_length)

        print("=" * 50)
        if result:
            print(f"[+] 找到密码: {result}")
        else:
            print("[-] 破解失败")

        return result


def main():
    parser = argparse.ArgumentParser(description='SHA1 密码破解工具 - 支持多进程')
    parser.add_argument('hash', help='目标 SHA1 哈希值')
    parser.add_argument('-w', '--wordlist', help='密码表文件路径')
    parser.add_argument('-s', '--salt', help='盐值（拼接到密码后面）')
    parser.add_argument('-c', '--charset',
                       default=string.ascii_lowercase + string.digits,
                       help='枚举字符集 (默认: a-z0-9)')
    parser.add_argument('--min-length', type=int, default=1, help='枚举最小长度 (默认: 1)')
    parser.add_argument('--max-length', type=int, default=6, help='枚举最大长度 (默认: 6)')

    args = parser.parse_args()

    cracker = SHA1Cracker(args.hash, args.wordlist, args.salt)
    cracker.crack(
        charset=args.charset,
        min_length=args.min_length,
        max_length=args.max_length
    )


if __name__ == '__main__':
    main()
