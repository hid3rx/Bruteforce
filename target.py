# coding=utf-8
#
# ============================================================================
#   target.py — 针对目标网站的配置与爆破逻辑
#
#   【说明】每次开发一个新网站的弱口令检测脚本，只需要修改本文件：
#     1. 修改 configs 中的配置项（字典、超时、线程、代理等）
#     2. 修改 run() 函数中的登录逻辑（URL、请求参数、登录结果判断等）
#
#   【注意】main.py 是框架代码，一般不需要修改
# ============================================================================
#

import random
from curl_cffi import requests
from datetime import datetime
from framework import configs, info_message

#
# =================== [ 全局设置 ] ===================
#
# 以下修改会合并覆盖到框架的默认配置（框架默认配置见 framework.py）
# 只需要写你想要覆盖的配置项即可
#

configs.update({
    # 账户字典
    "account_list": {
        "username": [ "admin" ],
        "password": [ "123456" ]
    },

    # 字典文件（留空表示不使用文件）
    "account_file": {
        "username": r"", # /path/to/username.txt
        "password": r""  # /path/to/password.txt
    },

    # 爆破模式
    #   pitchfork   = 草叉模式（Yakit） / Pitchfork（Burpsuite）— 用户名密码按位置一一对应
    #   clusterbomb = 乘积模式（Yakit） / ClusterBomb（Burpsuite）— 尝试所有组合（笛卡尔积）
    "mode": "clusterbomb",

    # 超时时间，单位秒
    "timeout": 10,

    # 线程并发数（涉及验证码识别时建议设为 1）
    "threads": 10,

    # 每个线程发起请求后暂停时长，单位秒
    "delay": 1,

    # 是否使用代理
    "use_proxy": False,

    # 代理地址（仅 use_proxy=True 时生效）
    "proxies": {
        "http": "http://127.0.0.1:8080",
        "https": "http://127.0.0.1:8080"
    },

    # 自定义请求头
    "headers": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0",
        "Connection": "close",
        # "X-Requested-With": "XMLHttpRequest",
    },

    # 自定义Cookies
    "cookies": {
        # "JSESSIONID": "",
    },
})

#
# =================== [ 爆破函数 ] ===================
#
# 本函数由线程池自动调度，每调用一次发起一次登录操作。
# 参数 username 和 password 由框架根据爆破模式自动填充。
#

def run(username, password):
    # -------- 构造请求头（自动伪造IP头） --------
    headers = configs["headers"].copy()
    random_ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
    headers.update({
        "X-Forwarded-For": random_ip,
        "X-Originating-IP": random_ip,
        "X-Remote-IP": random_ip,
        "X-Remote-Addr": random_ip,
        "X-Real-IP": random_ip
    })
    cookies = configs["cookies"].copy()
    proxies = configs["proxies"] if configs["use_proxy"] else None

    url = "https://example.com"
    # curl_cffi 模拟真实浏览器TLS指纹，可选: firefox133, chrome131 等
    session = requests.Session(impersonate="firefox133")

    # -------- [可选] 加密/哈希密码 --------
    # from utils import crypto
    # password = crypto.DES_encrypt(password)     # DES加密 → Base64
    # password = crypto.AES_encrypt(password)     # AES加密 → Base64
    # password = crypto.RSA_encrypt(password)     # RSA加密 → Base64
    # password = crypto.MD5_hash(password)        # MD5哈希 → HEX
    # password = crypto.HMAC_hash(password)       # HMAC-SHA256 → HEX
    # password = crypto.Base64_encode(password)   # Base64编码

    # -------- [可选] 执行JS脚本获取签名 --------
    # from utils import execjs
    # signature = execjs.signature(password)
    # # 需要先修改 utils/execjs.py 中的函数，以及编写对应的JS脚本

    # -------- [可选] 识别图片验证码 --------
    # from utils import captchadet
    # ocr = captchadet.DdddOcr()      # 通用验证码识别
    # # ocr = captchadet.RuoyiOcr()   # 若依框架验证码识别
    #
    # response = session.get(url + "/captcha", headers=headers, cookies=cookies,
    #     proxies=proxies, verify=False, timeout=configs["timeout"])
    #
    # # 方式一：响应体是图片字节流
    # captcha = ocr.identify_image_bytes(response.content)
    # # 方式二：响应体是内联Base64图片（如 data:image/png;base64,iVBOR...）
    # # captcha = ocr.identify_image_inline(response.text)

    # -------- [可选] 用XPath从登录页提取CSRF Token --------
    # from lxml import etree
    # response = session.get(url + "/login", headers=headers, cookies=cookies,
    #     proxies=proxies, verify=False, timeout=configs["timeout"])
    # html = etree.HTML(response.text, etree.HTMLParser())
    # csrftoken = html.xpath('//input[@type="hidden" and @id="csrf"]/@value')[0]

    # -------- 内置重试机制 --------
    # 在某种条件下可以尝试重复请求，如验证码识别错误、服务器响应502等
    error = {}
    error["502"] = 0
    # error["captcha"] = 0
    while True:

        # -------- 构造请求体并发起登录请求 --------
        data = {
            "username": username,
            "password": password
        }
        response = session.post(url + "/login.html",
            json=data, cookies=cookies, headers=headers, proxies=proxies,
            verify=False, allow_redirects=False, timeout=configs["timeout"])

        # -------- 重试判断 --------
        if response.status_code == 502:
            error["502"] += 1
            if error["502"] > 5:
                raise Exception("Server internal error")
            continue
        # elif "验证码有误" in response.text:
        #     error["captcha"] += 1
        #     if error["captcha"] > 5:
        #         raise Exception("Incorrect captcha")
        #     continue
        else:
            break

    # -------- 判断登录结果 --------
    #
    # 思路：一般能知道"失败"返回什么，而不知道"成功"返回什么，
    #       因此 if/elif 写失败条件，else 处理成功。
    #
    # 常见判断方式（根据实际场景选择）：
    # if len(response.content) == 100:
    # if response.status_code == 401:
    # if "Login failed" in response.text:
    # if response.status_code == 302 and "login" in response.headers.get("Location", ""):

    if "用户不存在" in response.text:  # 失败条件1
        return

    elif "密码错误" in response.text:  # 失败条件2
        return

    else:  # 登录成功
        info_message(f"[++] {datetime.now().strftime('%H:%M:%S')} Found {username}:{password}\t\t=> code:{response.status_code} length:{len(response.content)}")
        return
