"""文件名和日志中的敏感片段脱敏。"""
import re


# 文件名没有赋值上下文，长标识统一遮蔽，可能同时隐藏普通名称。
_TOKEN = re.compile(r'[A-Za-z0-9_-]{20,}')
_CONTROLS = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')


def safe_text(value):
    value = str(value)
    return _TOKEN.sub('[已脱敏]', _CONTROLS.sub('', value))
