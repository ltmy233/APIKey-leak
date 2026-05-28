# APIKey Leak

GitHub 上搜索 AI 厂商意外泄露的 API Key，自动验证有效性和查询余额。

## 能干什么

很多开发者在提交代码时，不小心把 API Key 一起传到了 GitHub。这个工具可以批量扫描 GitHub 公开仓库，找出这些泄露的密钥，并自动验证是否还有效、还剩多少余额。

**覆盖 19 家 AI 厂商：** OpenAI / DeepSeek / Anthropic / Google AI / HuggingFace / xAI / Cohere / Replicate / Together AI / Mistral / Groq / Perplexity / Jina AI / Voyage AI / Fireworks AI / DeepInfra / Novita AI / SiliconFlow / AI21 Labs

## 工作原理

1. 用 GitHub Token 调用 Code Search API，搜索包含密钥特征的文件
2. 用正则提取疑似密钥
3. 调用各厂商 API 验证密钥是否有效
4. 查询可用模型 + 余额

## 安装

```bash
pip install aiohttp
```

## 快速开始

### 第一步：准备 GitHub Token

打开 https://github.com/settings/tokens → **Generate new token (classic)** → 不用勾任何权限 → 生成后复制。

Token 越多扫描越快，建议准备 3~5 个。代码搜索共享 10 次/分钟限额，同账号多 Token 不会叠加。

### 第二步：启动

```bash
python APIKey_leak.py
```

### 第三步：按提示配置

```
[1/4] 配置GitHub Token
  粘贴 Token，支持多个用逗号/空格/换行分隔
  输入完回车确认，可保存到本地下次直接加载

[2/4] 选择厂商
  输入序号，多选用逗号隔开，1-5 框选，回车=全选

[3/4] 搜索范围
  输入页码范围，如 1~10，范围越大搜得越多越慢

[4/4] 排序方式
  1. 最新优先  ← 默认
  2. 最早优先
  3. 最佳匹配
```

然后输入 `y` 开始扫描，等待结果。

### 输出结果

扫描完成后会显示每个密钥的：
- 厂商、密钥内容
- 来源仓库链接
- 可用模型列表
- 账户余额

同时会保存 `api_key_leak_results.txt`，支持 `--csv result.csv` 导出 CSV。

## 命令行模式

不想交互？一波带参数跑完：

```bash
python APIKey_leak.py \
  --token "ghp_xxx,ghp_yyy,ghp_zzz" \
  --providers OPENAI DEEPSEEK ANTHROPIC \
  --start-page 1 --end-page 5 \
  --csv result.csv \
  --no-interactive
```

## 参数说明

| 参数 | 默认 | 说明 |
|------|------|------|
| `--token` | - | GitHub Token，多个逗号分隔 |
| `--providers` | 全部 | 厂商名，如 `OPENAI DEEPSEEK` |
| `--start-page` | 1 | 起始页，每页最多 100 条 |
| `--end-page` | 3 | 结束页，上限 10 页（GitHub 限制） |
| `--sort` | `indexed` | 排序字段，留空=最佳匹配 |
| `--order` | `desc` | `desc` 降序 / `asc` 升序 |
| `--search-rate` | 10 | 代码搜索限速（次/分钟） |
| `--concurrency` | 25 | 验证并发数 |
| `--output` | `api_key_leak_results.txt` | 结果输出路径 |
| `--csv` | - | 同时导出 CSV |
| `--no-interactive` | - | 跳过交互，直接扫描 |

## 排序

| 选项 | 对应参数 | 效果 |
|------|----------|------|
| 最新优先 | `--sort indexed --order desc` | 最近索引的文件在前（默认） |
| 最早优先 | `--sort indexed --order asc` | 最早索引的文件在前 |
| 最佳匹配 | `--sort ""` | GitHub 默认相关度 |

## 多 Token 怎么来

多个 token 可以分摊请求频率，避免单个 token 被限流。但同账号的 token 共享 `code_search` 额度（10次/分钟），所以并发上不去时不必强求更多 token。

## 免责声明

**仅限以下用途：**
- 授权的安全研究和渗透测试
- 自己仓库的密钥泄漏自查
- 安全教育和学术研究

使用者自行承担所有法律责任。
