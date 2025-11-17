# coding=utf-8
# Install this https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist

import base64, ddddocr

# 初始化模型
def init():
    return ddddocr.DdddOcr(show_ad=False)

# 识别验证码，参数为图像字节
def identify_image(ocr, image: bytes):
    return ocr.classification(image)

# 识别验证码，参数为内联图像，image="data:image/png;base64,iVBO..."
def identify_inline_image(ocr, image: str):
    image = image.replace("data:image/png;base64,", "")
    image = base64.b64decode(image)
    return ocr.classification(image)
