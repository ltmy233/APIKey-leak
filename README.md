# APIKey Leak

## v1.3 桌面版

新增图形化界面，优化扫描并发、重复文件处理、取消响应和异常提示。Windows x64 可直接运行 EXE，无需安装 Python。

- [下载 APIKeyLeak.exe](https://github.com/ltmy233/APIKey-leak/releases/download/v1.3/APIKeyLeak.exe)
- [下载 SHA-256 校验文件](https://github.com/ltmy233/APIKey-leak/releases/download/v1.3/APIKeyLeak.exe.sha256)
- [查看 v1.3 发行页面](https://github.com/ltmy233/APIKey-leak/releases/tag/v1.3) · [更新说明](docs/release-v1.3.md) · [验证记录](docs/verification-2026-11-01.md)

## 新增：授权仓库自查 ClickGUI

基于 **PySide6** 的原生桌面界面，支持指定 GitHub 用户后勾选其公开仓库，或直接指定单个仓库。新 GUI **仅离线识别疑似泄漏**：不会调用发现的密钥验证有效性，不查询模型或余额，也不导出完整密钥。

### 安装和启动

从上方下载 `APIKeyLeak.exe`，双击即可启动，不需要安装 Python。自行从源码构建时，产物位于项目内的 `dist\APIKeyLeak.exe`。程序使用项目原有图标。

EXE 为未签名版本，Windows 可能提示未知发布者；请核对来源，不要关闭系统安全防护。首次启动需要解压运行库，可能比后续启动慢。仅在 Windows x64 上构建和验证。

### 从源码运行

推荐 Python 3.10 或更高版本，在项目目录执行：

```powershell
python -m pip install -r requirements-gui.txt
python gui.py
```

如果默认 PyPI 网络不可达，可按自己的网络环境配置可访问的包镜像。Windows 下建议使用系统原生 Qt 平台运行，不要设置 `QT_QPA_PLATFORM=offscreen`；该平台仅供自动化测试，可能没有系统字体。

### 重新构建 EXE

在项目目录执行：

```powershell
python -m pip install -r requirements-build.txt
powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
```

`build.ps1` 调用 PyInstaller，生成无控制台的单文件程序 `dist\APIKeyLeak.exe`，同时嵌入窗口图标。构建依赖只用于打包，使用 EXE 无需安装依赖。当前构建环境为 Python 3.14.6、PyInstaller 6.21.0、PySide6 6.11.2。

### 使用流程

1. 在“扫描范围”选择 **指定用户** 或 **指定仓库**。
2. 用户模式填写用户名或用户主页链接，点击“加载用户仓库”，勾选获授权的目标；仓库模式填写 `owner/repo` 或仓库主页链接，点击“读取指定仓库”。
3. GitHub Token 可选。公开仓库可以不填写；私有仓库需要具有仓库 Contents 读取权限的 Token，并使用指定仓库模式。支持 classic 和 fine-grained Token。
4. 选择需要检测的厂商，勾选“我拥有所选仓库的扫描授权”，点击“开始自查”。
5. 在结果表按厂商、仓库或文件名筛选；双击一行并确认后可在浏览器定位源码。`Ctrl+C` 复制选中行的脱敏记录。
6. “导出报告”支持 JSON / CSV / TXT，导出 **所有已收到记录**，不只导出当前筛选行。CSV 对文件名等文本做公式注入防护。

### 界面与处理逻辑

- 深色侧栏、可调整左右分栏、实时统计、结果表、运行日志与使用说明。
- GitHub 网络请求在可取消的后台线程运行；主线程不等待网络，关闭窗口会先取消任务再释放线程。
- 下载并发默认 4，可调 1–16；同一仓库的相同 blob 只下载和识别一次，但保留不同文件路径的证据。
- 对分页仓库列表和被截断的递归目录树做完整读取；文件内容和定位链接锁定同一提交快照。
- Token 失效、限流、网络失败显式提示；瞬时故障有限重试，不把错误吞掉后显示“无发现”。
- 结果模型批量更新，记录 SHA-256 指纹、脱敏片段、仓库、文件及行号；指纹相同的不同位置不会丢失。
- GitHub Token 只保留在内存，不保存到原 CLI 的 `.token_store.json`；输入默认隐藏，关闭窗口清空。
- 文件名、仓库名和日志中的长疑似敏感标识也会保守脱敏；可能同时遮蔽普通长名称。若定位元数据被脱敏，禁用直达源码链接，需在仓库内手动定位。
- 导出附带扫描状态、覆盖计数及并发/文件大小配置，保留“取消”“失败”“部分完成”的语义，避免部分结果被当成完整结论。

### 自查范围与限制

- **仅限自有或已明确获授权的仓库。** 用户模式只列公开仓库；不会自动扫描所有搜索结果。
- 只检查默认分支当前快照，不包括历史提交、其他分支、子模块或 Git LFS 的实际大文件内容。
- 默认跳过依赖/构建目录（如 `node_modules`、`.venv`、`vendor`、`dist`、`build`）、常见二进制和超过 1 MB 的文件。文件上限可调到 8 MB。
- 非 UTF-8 内容、含空字节的二进制和超过 32768 字符的超长单行不做识别；可能漏掉部分压缩或特殊编码文件。
- 采用格式和同一行赋值上下文判断，**可能误报或漏报，不能证明密钥有效**。无法判断厂商的 `sk-` 格式会标注“厂商待确认”。
- 取消或出现读取失败时，只保留已收到的部分结果，不是完整扫描结论。未发现也不意味着仓库绝对没有泄漏。
- 发现疑似泄漏后，应由所有者在厂商控制台撤销/轮换凭据，再清理代码及 Git 历史。
- 读取遵循 `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`。代理端口无效时先修正环境配置；仓库已重命名时填写最新名称。

### 测试

```powershell
python -m unittest discover -s tests -v
python -m compileall -q keyaudit gui.py APIKey_leak.py
```

测试使用合成凭据、本地 HTTP 服务和 Qt 自动化，不调用真实厂商接口。覆盖输入校验、脱敏导出、分页、目录树截断、下载去重、限流、失败中止、取消清理、完整点击流程和大批量结果筛选。

> **兼容性说明：** `python APIKey_leak.py` 仍是原命令行入口，其原有行为未改为 GUI 的安全自查流程。以下章节描述旧 CLI，不适用于新 GUI。新 GUI 中没有验证密钥、余额查询或完整密钥导出功能。

---

## 原命令行版本

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
