import requests

headers = {

    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
}

response = requests.get('https://www.baidu.com/',  headers=headers, proxies={'https':'http://xxx:xxx@127.0.0.1:8080'})
print(response.content)