import subprocess

# 本模块负责执行JS代码，需要手动下载 QuickJS 并将路径添加到环境变量中，并确保 QuickJS 的程序名与 quickjs 变量一致
# 仓库地址：https://github.com/quickjs-ng/quickjs
quickjs = "qjs.exe"

# 执行特定功能，需要针对目标场景自行编写函数
def signature(data):
    evalcode = f"go('{data}')"
    output = subprocess.check_output([quickjs, "--std", "-I", "signature.js", "-e", evalcode])
    return output.decode("utf-8")
