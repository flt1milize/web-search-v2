# web-search v3.1.0 MCP Server

基于 Bing 搜索引擎的 MCP 服务器，提供**网页搜索**、**图片搜索**、**新闻搜索**、**视频搜索**和**网页内容抓取**，纯 Python 标准库零依赖。

## 功能

| 工具 | 说明 |
|------|------|
| `search_web` | 搜索网络（Bing 中英双语），支持时间/安全/分页过滤 |
| `search_images` | 搜索图片，返回 URL、尺寸、来源页面 |
| `search_news` | 搜索新闻，返回标题、日期、来源 |
| `search_videos` | 搜索视频，返回缩略图、时长、播放量 |
| `fetch_webpage` | 获取网页文本内容（自动识别 JSON） |
| `fetch_markdown` | 获取网页并转为 Markdown |
| `cache_stats` | 查看缓存和限速状态 |

## 特性

- **多类型搜索** — 网页 / 图片 / 新闻 / 视频
- **双语言搜索** — 自动合并中文（zh-Hans）+ 英文（en）结果
- **搜索参数丰富** — freshness / safesearch / offset / country / search_lang
- **搜索结果元数据** — 拼写建议、相关搜索、总数估算
- **Tool 启禁控制** — WS_ENABLED_TOOLS / WS_DISABLED_TOOLS
- **反爬保护** — 多 UA 轮换、自适应退避、限速控制
- **LRU 缓存** — 可配置 TTL，支持 no_cache 跳过
- **SSRF 防护** — 私有地址 + DNS rebinding 双重检测
- **HTML→Markdown** — 纯标准库实现，支持表格/列表/代码/链接
- **正文提取** — 启发式评分提取文章主要内容
- **零依赖** — 仅使用 Python 标准库
- **双传输模式** — STDIO（默认）+ HTTP（--transport http）

## 环境要求

- Python 3.8+

## 快速开始

### 克隆仓库

```bash
git clone https://github.com/flt1milize/web-search-v2.git
cd web-search-v2
```

### 在 Cline 中使用

将以下内容添加到 Cline 的 MCP 配置中（`cline_mcp_settings.json`）：

```json
{
  "mcpServers": {
    "web-search v3.1.0": {
      "autoApprove": [
        "search_web",
        "search_images",
        "search_news",
        "search_videos",
        "fetch_webpage",
        "fetch_markdown",
        "cache_stats"
      ],
      "disabled": false,
      "timeout": 120,
      "type": "stdio",
      "command": "python",
      "args": ["-u", "/path/to/web-search-v2/server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `WS_CACHE_TTL` | `300` | 缓存 TTL（秒） |
| `WS_CACHE_CAP` | `256` | 缓存容量 |
| `WS_RETRY` | `2` | 请求重试次数 |
| `WS_TIMEOUT` | `15` | 请求超时（秒） |
| `WS_TRANSPORT` | `stdio` | 传输模式：stdio / http |
| `WS_HTTP_PORT` | `8080` | HTTP 端口 |
| `WS_HTTP_HOST` | `0.0.0.0` | HTTP 主机 |
| `WS_STATELESS` | `false` | 无状态 HTTP 模式 |
| `WS_ENABLED_TOOLS` | - | 工具白名单（空格分隔） |
| `WS_DISABLED_TOOLS` | - | 工具黑名单（空格分隔） |
| `WS_DEFAULT_LIMIT` | `5000` | 抓取默认最大字符数 |
| `LOG_LEVEL` | `INFO` | 日志级别 |
| `HTTP_PROXY` / `HTTPS_PROXY` | - | HTTP 代理地址 |

## 命令行参数

```bash
# STDIO 模式（默认）
python server.py

# HTTP 模式
python server.py --transport http --port 8080

# 无状态 HTTP 模式
python server.py --transport http --stateless
```

## 许可证

MIT