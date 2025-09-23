import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

url = "https://www.sustech.edu.cn/"
resp = requests.get(url)
soup = BeautifulSoup(resp.text, "html.parser")

# 提取常见资源
resources = set()
for tag, attr in [("img", "src"), ("script", "src"), ("link", "href")]:
    for t in soup.find_all(tag):
        src = t.get(attr)
        if src:
            resources.add(urljoin(url, src))

print("资源文件列表：")
for r in resources:
    print(r)

import mimetypes

print("\n文件及其猜测的MIME类型：")
for r in resources:
    mime_type, _ = mimetypes.guess_type(r)
    print(f"{r} -> {mime_type}")

for r in resources:
    try:
        res = requests.head(r, timeout=5)
        content_type = res.headers.get('Content-Type')
        print(f"{r} -> {content_type}")
    except Exception as e:
        print(f"{r} -> 请求失败")