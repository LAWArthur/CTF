#!/usr/bin/env python3
"""
Flask 重定向服务器 - 将所有请求重定向到指定网站
支持两种模式：
  1. 固定模式：所有请求都重定向到目标 URL 本身（丢弃原始路径）
  2. 保留模式：保留原始路径和参数（默认）
支持命令行参数配置
"""

import argparse
import sys
from urllib.parse import urljoin
from flask import Flask, redirect, request

app = Flask(__name__)

# 全局配置变量
TARGET_URL = 'https://example.com'
REDIRECT_CODE = 301
EXCLUDE_PATHS = []
PORT = 8080
HOST = '0.0.0.0'
PRESERVE_PATH = True  # True: 保留路径, False: 固定重定向到根

@app.before_request
def redirect_all():
    """拦截所有请求并重定向"""
    
    # 检查是否在排除列表中
    if request.path in EXCLUDE_PATHS:
        return None
    
    if PRESERVE_PATH:
        # 模式 1：保留原始路径和参数
        target_url = urljoin(TARGET_URL, request.full_path.lstrip('/'))
    else:
        # 模式 2：固定重定向到目标 URL 本身（丢弃路径和参数）
        target_url = TARGET_URL
        # 如果目标 URL 本身包含路径（如 https://example.com/blog），保留它
        # 但丢弃请求中的路径
    
    return redirect(target_url, code=REDIRECT_CODE)

@app.route('/health', methods=['GET', 'HEAD'])
def health():
    """健康检查端点"""
    return {
        "status": "ok",
        "redirect_to": TARGET_URL,
        "mode": "preserve_path" if PRESERVE_PATH else "fixed_root"
    }, 200

@app.route('/config', methods=['GET'])
def config():
    """查看当前配置（调试用）"""
    return {
        "target_url": TARGET_URL,
        "redirect_code": REDIRECT_CODE,
        "exclude_paths": EXCLUDE_PATHS,
        "host": HOST,
        "port": PORT,
        "preserve_path": PRESERVE_PATH,
        "mode": "保留路径" if PRESERVE_PATH else "固定根路径"
    }

@app.route('/debug/url', methods=['GET'])
def debug_url():
    """调试端点：显示当前请求和目标 URL"""
    if PRESERVE_PATH:
        redirect_url = urljoin(TARGET_URL, request.full_path.lstrip('/'))
    else:
        redirect_url = TARGET_URL
    
    return {
        "target_url": TARGET_URL,
        "request_full_path": request.full_path,
        "redirect_url": redirect_url,
        "redirect_code": REDIRECT_CODE,
        "mode": "preserve_path" if PRESERVE_PATH else "fixed_root"
    }

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description='Flask 重定向服务器 - 将所有请求重定向到指定网站',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例：
  # 保留路径模式（默认）：/api/test -> https://example.com/api/test
  python redirect_server.py -t https://example.com

  # 固定根路径模式：所有请求 -> https://example.com/
  python redirect_server.py -t https://example.com --fixed

  # 目标 URL 带路径：/api/test -> https://example.com/blog/
  python redirect_server.py -t https://example.com/blog --fixed

  # 使用 302 临时重定向，监听 9000 端口
  python redirect_server.py -t https://example.com -c 302 -p 9000

  # 排除健康检查路径
  python redirect_server.py -t https://example.com -e /health /api/webhook
        """
    )
    
    parser.add_argument(
        '-t', '--target',
        dest='target_url',
        help='目标重定向 URL（例如：https://example.com）',
        default=None
    )
    
    parser.add_argument(
        '-c', '--code',
        dest='redirect_code',
        type=int,
        choices=[301, 302, 303, 307, 308],
        default=301,
        help='HTTP 重定向状态码（默认：301）'
    )
    
    parser.add_argument(
        '-p', '--port',
        dest='port',
        type=int,
        default=8080,
        help='监听端口（默认：8080）'
    )
    
    parser.add_argument(
        '--host',
        dest='host',
        default='0.0.0.0',
        help='监听地址（默认：0.0.0.0 表示所有接口）'
    )
    
    parser.add_argument(
        '-e', '--exclude',
        dest='exclude_paths',
        nargs='+',
        default=[],
        help='排除的路径（不重定向），例如：/health /api/webhook'
    )
    
    parser.add_argument(
        '--fixed',
        dest='fixed',
        action='store_true',
        help='固定模式：所有请求都重定向到目标 URL 本身（丢弃原始路径）'
    )
    
    parser.add_argument(
        '--preserve',
        dest='preserve',
        action='store_true',
        help='保留路径模式：保留原始路径和参数（默认行为）'
    )
    
    parser.add_argument(
        '--debug',
        dest='debug',
        action='store_true',
        help='启用调试模式'
    )
    
    return parser.parse_args()

def load_config_from_env():
    """从环境变量加载配置"""
    import os
    return {
        'target_url': os.environ.get('TARGET_URL'),
        'redirect_code': int(os.environ.get('REDIRECT_CODE', 301)),
        'port': int(os.environ.get('PORT', 8080)),
        'host': os.environ.get('HOST', '0.0.0.0'),
        'exclude_paths': os.environ.get('EXCLUDE_PATHS', '').split(',') if os.environ.get('EXCLUDE_PATHS') else [],
        'preserve_path': os.environ.get('PRESERVE_PATH', 'true').lower() != 'false'
    }

def validate_target_url(url):
    """验证目标 URL 是否有效"""
    if not url:
        print("❌ 错误：未指定目标 URL", file=sys.stderr)
        print("   请使用 -t 参数或设置 TARGET_URL 环境变量", file=sys.stderr)
        print("   例如：python redirect_server.py -t https://example.com", file=sys.stderr)
        sys.exit(1)
    
    if not (url.startswith('http://') or url.startswith('https://')):
        print(f"⚠️  警告：目标 URL 缺少协议，自动添加 https://", file=sys.stderr)
        url = 'https://' + url
    
    return url

def get_mode_desc(preserve):
    """获取模式描述"""
    return "保留路径（preserve_path）" if preserve else "固定根路径（fixed_root）"

def get_status_desc(code):
    """获取状态码描述"""
    status_map = {
        301: "永久重定向",
        302: "临时重定向",
        303: "查看其他位置",
        307: "临时重定向（保持方法）",
        308: "永久重定向（保持方法）"
    }
    return status_map.get(code, "未知")

def main():
    """主函数"""
    # 1. 解析命令行参数
    args = parse_args()
    
    # 2. 从环境变量加载
    env_config = load_config_from_env()
    
    # 3. 合并配置（命令行 > 环境变量）
    global TARGET_URL, REDIRECT_CODE, PORT, HOST, EXCLUDE_PATHS, PRESERVE_PATH
    
    TARGET_URL = args.target_url or env_config.get('target_url') or 'https://example.com'
    TARGET_URL = validate_target_url(TARGET_URL)
    
    REDIRECT_CODE = args.redirect_code or env_config.get('redirect_code', 301)
    PORT = args.port or env_config.get('port', 8080)
    HOST = args.host or env_config.get('host', '0.0.0.0')
    EXCLUDE_PATHS = args.exclude_paths or env_config.get('exclude_paths', [])
    
    # 处理模式：--fixed 优先级高于 --preserve，命令行高于环境变量
    if args.fixed:
        PRESERVE_PATH = False
    elif args.preserve:
        PRESERVE_PATH = True
    else:
        # 从环境变量读取，默认为 True
        PRESERVE_PATH = env_config.get('preserve_path', True)
    
    # 4. 显示配置
    print("=" * 60)
    print("🚀 Flask 重定向服务器启动")
    print("=" * 60)
    print(f"📌 目标 URL:     {TARGET_URL}")
    print(f"🔄 重定向模式:   {get_mode_desc(PRESERVE_PATH)}")
    if PRESERVE_PATH:
        print(f"   └─ /api/test -> {TARGET_URL}/api/test")
    else:
        print(f"   └─ /api/test -> {TARGET_URL}/ (固定)")
    print(f"🔢 状态码:       {REDIRECT_CODE} ({get_status_desc(REDIRECT_CODE)})")
    print(f"🌐 监听地址:     {HOST}:{PORT}")
    print(f"🚫 排除路径:     {EXCLUDE_PATHS or '无'}")
    print(f"🐛 调试模式:     {'开启' if args.debug else '关闭'}")
    print("=" * 60)
    print(f"📍 健康检查:     http://{HOST if HOST != '0.0.0.0' else 'localhost'}:{PORT}/health")
    print(f"⚙️  配置查看:     http://{HOST if HOST != '0.0.0.0' else 'localhost'}:{PORT}/config")
    print(f"🔍 调试URL:      http://{HOST if HOST != '0.0.0.0' else 'localhost'}:{PORT}/debug/url")
    print("=" * 60)
    print("按 Ctrl+C 停止服务器")
    print()
    
    # 5. 启动服务器
    try:
        app.run(host=HOST, port=PORT, debug=args.debug)
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"❌ 错误：端口 {PORT} 已被占用，请使用 -p 指定其他端口", file=sys.stderr)
        else:
            print(f"❌ 错误：{e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()