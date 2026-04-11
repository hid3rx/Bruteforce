# Web弱口令安全检测工具

一个可定制的Web网站弱口令安全检测框架。针对每个目标网站，只需修改 `target.py` 中的配置和登录逻辑即可。

---

## 快速开始

```bash
pip install -r requirements.txt
python main.py
```

---

## 项目结构

```
main.py              # 程序入口（不需要修改）
framework.py         # 框架核心：线程池、字典加载、日志、进度汇报（不需要修改）
target.py            # ★ 目标网站配置 + 爆破函数（每次针对新网站时修改此文件）
requirements.txt     # Python依赖库
utils/
    crypto.py        # 加密/哈希工具（DES、AES、RSA、MD5、HMAC、Base64）
    execjs.py        # JS脚本执行（基于QuickJS）
    captchadet/      # 验证码识别模块
        ocr.py       # 统一封装（DdddOcr / RuoyiOcr）
        dddd/        # 通用验证码模型
        ruoyi/       # 若依验证码模型
test/
    signature.js     # JS脚本示例
```

### 文件职责划分

| 文件 | 是否需要修改 | 说明 |
|------|:---:|------|
| `target.py` | **是** | 每次针对新网站时修改：配置项 + `run()` 函数 |
| `utils/crypto.py` | 有时 | 需要修改加密密钥/公钥以匹配目标网站 |
| `utils/execjs.py` | 有时 | 需要自定义JS执行函数以匹配目标网站 |
| `main.py` | 否 | 入口文件，仅导入并启动 |
| `framework.py` | 否 | 框架核心，线程池/日志/字典加载 |

---

## 如何针对新网站编写检测脚本

**只需修改 `target.py`，完成以下两步：**

### 第一步：修改 `configs` 配置

```python
configs.update({
    "account_list": {
        "username": [ "admin", "test" ],
        "password": [ "123456", "admin123" ]
    },
    "account_file": {
        "username": r"",           # 留空 = 不使用字典文件
        "password": r"pass.txt"    # 指定密码字典文件路径
    },
    "mode": "clusterbomb",  # clusterbomb=所有组合 / pitchfork=一一对应
    "timeout": 10,
    "threads": 10,          # 涉及验证码识别时设为 1
    "delay": 1,             # 每次请求间隔（秒）
    "use_proxy": False,
})
```

### 第二步：修改 `run()` 函数

`run(username, password)` 负责发起**单次**登录请求并判断结果。框架会根据爆破模式自动调度。

核心流程：
1. 构造请求（URL、参数、headers）
2. 发起登录请求
3. 判断登录结果：`if` 写失败条件，`else` 处理成功

> 异常处理（try/except/finally）、请求延迟、异常计数、完成计数等由框架的 `run_wrapper` 自动处理，`run()` 中只需专注登录逻辑。如果遇到需要抛出的错误（如重试超限），直接 `raise` 即可，框架会捕获并记录。

```python
def run(username, password):
    # ... 前置代码（伪造IP头等，已内置）...

    url = "https://target-site.com"
    session = requests.Session(impersonate="firefox133")

    data = {"username": username, "password": password}
    response = session.post(url + "/api/login",
        json=data, cookies=cookies, headers=headers, proxies=proxies,
        verify=False, allow_redirects=False, timeout=configs["timeout"])

    # 判断登录结果：if/elif 写失败条件，else 处理成功
    if "用户名或密码错误" in response.text:
        return  # 登录失败
    else:
        info_message(f"[++] Found {username}:{password}")
        return  # 登录成功
```

---

## 可选功能用法

### 1. 密码加密/哈希

在 `run()` 函数中调用，需先根据目标网站修改 `utils/crypto.py` 中的密钥。

```python
from utils import crypto

password = crypto.DES_encrypt(password)     # DES-CBC加密 → Base64
password = crypto.AES_encrypt(password)     # AES-CBC加密 → Base64
password = crypto.RSA_encrypt(password)     # RSA加密 → Base64
password = crypto.MD5_hash(password)        # MD5哈希 → HEX
password = crypto.HMAC_hash(password)       # HMAC-SHA256 → HEX
password = crypto.Base64_encode(password)   # Base64编码
```

> `crypto.py` 中默认输出 Base64 格式，如需 HEX，取消注释 `binascii.hexlify` 那一行。

### 2. 执行JS脚本

需先安装 [QuickJS](https://github.com/quickjs-ng/quickjs) 并添加到系统 PATH。

```python
from utils import execjs

# 需要先修改 utils/execjs.py 中的函数逻辑，以及编写对应的JS脚本文件
signature = execjs.signature(password)
```

### 3. 验证码识别

```python
from utils import captchadet

ocr = captchadet.DdddOcr()      # 通用验证码
# ocr = captchadet.RuoyiOcr()   # 若依框架验证码

# 识别字节流图片
response = session.get(url + "/captcha", ...)
captcha = ocr.identify_image_bytes(response.content)

# 识别内联Base64图片（data:image/png;base64,...）
# captcha = ocr.identify_image_inline(response.text)
```

> 使用验证码识别时，将 `threads` 设为 1。

### 4. 提取CSRF Token

```python
from lxml import etree

response = session.get(url + "/login", ...)
html = etree.HTML(response.text, etree.HTMLParser())
csrftoken = html.xpath('//input[@type="hidden" and @id="csrf"]/@value')[0]
```

---

## 框架内置行为

以下行为由 `framework.py` 的 `run_wrapper` 和框架代码自动处理，无需在 `run()` 中手动实现：

- **请求延迟**：每次调用 `run()` 前自动 `sleep(configs["delay"])` 秒
- **异常捕获**：`run()` 中抛出的任何异常都会被框架捕获并记录到 `exception.txt`
- **异常计数**：`run()` 正常返回时重置连续异常计数；抛出异常时计数+1

- **伪造IP头**：每次请求自动生成随机 X-Forwarded-For / X-Real-IP 等
- **重试机制**：`run()` 内的 while 循环可针对 502、验证码错误等自动重试
- **异常保护**：连续异常超过 10 次自动停止所有线程
- **进度汇报**：每 10 分钟自动输出进度百分比
- **日志记录**：成功结果写入 `found.txt`，异常写入 `exception.txt`
- **键盘中断**：支持 `Ctrl+C` 安全退出
- **TLS指纹伪装**：`curl_cffi` 模拟真实浏览器指纹，可选 `firefox133`、`chrome131` 等

---

## 依赖说明

| 库 | 用途 |
|---|---|
| curl_cffi | HTTP请求，支持浏览器TLS指纹模拟 |
| lxml | HTML解析（XPath提取CSRF Token等） |
| pycryptodome | 加密算法（DES/AES/RSA/MD5/HMAC） |
| opencv-python | 验证码图像预处理 |
| numpy | 数值计算 |
| onnxruntime | ONNX模型推理（验证码识别） |

> 可选：Windows 首次使用 onnxruntime 可能需要安装 [VC运行时](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist)

+ 每个线程运行期间如果遭遇异常，会累加异常计数；如果下一个线程能正常完成请求，异常计数归零；连续异常累计超过10次时程序自动退出，避免无意义的请求

+ 成功找到的密码会记录在 `found.txt` 文件里；遭遇异常的密码会记录在 `exception.txt` 中，方便后续重新尝试
