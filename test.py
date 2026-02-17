import requests

def get(payload):
    url = "http://challenge-af279ac4f520cbbe.sandbox.ctfhub.com:10800/"
    headers = { "Referer": payload }
    response = requests.get(url, headers=headers)
    return response.content

while(True):
    payload = input()
    print(get(payload))