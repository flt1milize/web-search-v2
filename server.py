# -*- coding: utf-8 -*-
"""web-search v3.1.0 MCP Server — Bing多模态搜索 + 网页抓取

改进内容（参考 brave-search-mcp-server）：
  - 搜索参数丰富度：freshness/safesearch/offset/country/search_lang
  - 多类型搜索：search_web / search_images / search_news / search_videos
  - 搜索结果结构化优化：site_name/type/日期/来源/缩略图/时长/播放量
  - Tool启禁配置：WS_ENABLED_TOOLS / WS_DISABLED_TOOLS
  - 缓存控制增强：no_cache参数 + cache_stats Tool
  - 请求头白名单：ALLOWED_CUSTOM_HEADERS
  - 请求频率限制暴露：_rate_limit状态
  - 日志体系完善：trace_id/耗时追踪/debug级别
  - 搜索结果附加信息：拼写建议/相关搜索/总数估算
  - HTTP传输支持：--transport http 双模式 + --stateless
  - 可配置超时/重试：WS_TIMEOUT / WS_RETRY

  保留能力: SSRF防护 / 流式读取 / HTML→Markdown / 正文提取 / 表格转换 / JSON检测 / LRU缓存 / 自适应限速
"""
import gzip, html as _html, json, logging, os, random, re, socket, ssl, sys, threading, time, uuid
from collections import OrderedDict
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from urllib.parse import urlencode, urlparse
from urllib.request import Request, build_opener, ProxyHandler, HTTPCookieProcessor, HTTPSHandler
from urllib.error import HTTPError, URLError
from ipaddress import ip_address
from typing import Optional

# ═══════════════════════════════════════════════════════════════
# 日志 — trace_id / 耗时追踪
# ═══════════════════════════════════════════════════════════════
LV = os.environ.get('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(level=getattr(logging, LV, logging.INFO),
                    format='[ws] %(asctime)s %(msg)s', stream=sys.stderr, datefmt='%H:%M:%S')
log = logging.getLogger('ws')

def _trace_id() -> str: return uuid.uuid4().hex[:8]
def _log_timing(tid: str, label: str, start: float):
    log.debug(f'[{tid}] {label}: {(time.time() - start) * 1000:.0f}ms')

# ═══════════════════════════════════════════════════════════════
# 配置 — 所有关键参数可通过环境变量配置
# ═══════════════════════════════════════════════════════════════
CFG = {
    'ttl': int(os.environ.get('WS_CACHE_TTL', '300')),
    'cap': int(os.environ.get('WS_CACHE_CAP', '256')),
    'retry': int(os.environ.get('WS_RETRY', '2')),
    'max_response': int(os.environ.get('WS_MAX_RESPONSE_BYTES', str(2 << 20))),
    'timeout': int(os.environ.get('WS_TIMEOUT', '15')),
    'proxy': os.environ.get('HTTP_PROXY') or os.environ.get('HTTPS_PROXY') or None,
    'default_limit': int(os.environ.get('WS_DEFAULT_LIMIT', '5000')),
    'transport': os.environ.get('WS_TRANSPORT', 'stdio'),
    'http_port': int(os.environ.get('WS_HTTP_PORT', '8080')),
    'http_host': os.environ.get('WS_HTTP_HOST', '0.0.0.0'),
    'stateless': os.environ.get('WS_STATELESS', '').lower() == 'true',
}

ENABLED_TOOLS = [t.strip() for t in os.environ.get('WS_ENABLED_TOOLS', '').split() if t.strip()]
DISABLED_TOOLS = [t.strip() for t in os.environ.get('WS_DISABLED_TOOLS', '').split() if t.strip()]
if ENABLED_TOOLS and DISABLED_TOOLS:
    log.error('WS_ENABLED_TOOLS 与 WS_DISABLED_TOOLS 不能同时使用'); sys.exit(1)

def is_tool_permitted(name: str) -> bool:
    if ENABLED_TOOLS: return name in ENABLED_TOOLS
    if DISABLED_TOOLS: return name not in DISABLED_TOOLS
    return True

UA = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1',
]
BASE_HDR = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate', 'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Cache-Control': 'max-age=0', 'Connection': 'keep-alive', 'DNT': '1',
}

ALLOWED_CUSTOM_HEADERS = frozenset({
    'User-Agent', 'Accept', 'Accept-Language', 'Accept-Encoding',
    'Referer', 'Cookie', 'Authorization', 'X-Forwarded-For',
    'X-Requested-With', 'Origin', 'Cache-Control', 'DNT',
})

# ═══════════════════════════════════════════════════════════════
# SSRF 防护
# ═══════════════════════════════════════════════════════════════
_PRIVATE_HOSTS = frozenset({'localhost','127.0.0.1','0.0.0.0','::1','[::1]','0:0:0:0:0:0:0:1','[0:0:0:0:0:0:0:1]'})
def _is_private_host(h: str) -> bool:
    b = h.lower()
    if b.startswith('[') and b.endswith(']'): b = b[1:-1]
    if b in _PRIVATE_HOSTS: return True
    if b.endswith('.local') or b.endswith('.localhost'): return True
    try: return ip_address(b).is_private
    except ValueError: return False

def _resolve_and_check(h: str) -> None:
    b = h.lower()
    if b.startswith('[') and b.endswith(']'): b = b[1:-1]
    try:
        a = socket.gethostbyname(b)
        if ip_address(a).is_private: raise ValueError(f'DNS {b}->{a} 为私有IP')
    except socket.gaierror: pass

def validate_url(url: str) -> str:
    try: p = urlparse(url)
    except Exception: raise ValueError(f'无效URL: {url[:100]}')
    if p.scheme not in ('http','https'): raise ValueError(f'不支持协议 {p.scheme}')
    h = p.hostname
    if not h: raise ValueError(f'无法解析主机名: {url[:100]}')
    if _is_private_host(h): raise ValueError(f'拒绝私有地址 {h}（SSRF）')
    _resolve_and_check(h)
    return url

# ═══════════════════════════════════════════════════════════════
# 参数校验 — 支持 enum / pattern / required / default / min / max / max_len
# ═══════════════════════════════════════════════════════════════
def _check_type(v, exp, n):
    if exp=='str' and not isinstance(v,str): raise ValueError(f'{n} 应为字符串')
    if exp=='int' and not isinstance(v,(int,float)): raise ValueError(f'{n} 应为整数')
    if exp=='bool' and not isinstance(v,bool):
        if isinstance(v,str):
            if v.lower() in ('true','1'): return True
            if v.lower() in ('false','0'): return False
        raise ValueError(f'{n} 应为布尔值')
    if isinstance(v,float) and exp=='int': v=int(v)
    return v

def validate_args(args: dict, schema: dict) -> dict:
    r = {}
    for k, rules in schema.items():
        v = args.get(k)
        if v is None and 'default' in rules: v = rules['default']
        if rules.get('required') and (v is None or (isinstance(v,str) and not v.strip())):
            raise ValueError(f'缺少必填参数: {k}')
        if v is not None:
            t = rules.get('type')
            if t: v = _check_type(v, t, k)
            if 'min' in rules and v < rules['min']: raise ValueError(f'{k} < {rules["min"]}')
            if 'max' in rules and v > rules['max']: raise ValueError(f'{k} > {rules["max"]}')
            if 'max_len' in rules and isinstance(v,str) and len(v) > rules['max_len']:
                raise ValueError(f'{k} 超过最大长度 {rules["max_len"]}')
            if 'enum' in rules and v not in rules['enum']:
                raise ValueError(f'{k} 不支持值 "{v}", 可选: {rules["enum"]}')
            if 'pattern' in rules and isinstance(v,str) and not re.match(rules['pattern'], v):
                raise ValueError(f'{k} 格式不匹配: {v}')
        r[k] = v
    return r

# ═══════════════════════════════════════════════════════════════
# SSL & 网络
# ═══════════════════════════════════════════════════════════════
_cookiejar = CookieJar()
def _make_opener(verify=True):
    ctx = ssl.create_default_context()
    if not verify: ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    handlers = [HTTPCookieProcessor(_cookiejar)]
    if CFG['proxy']: handlers.insert(0, ProxyHandler({'http':CFG['proxy'],'https':CFG['proxy']}))
    handlers.append(HTTPSHandler(context=ctx))
    return build_opener(*handlers)

# ═══════════════════════════════════════════════════════════════
# 自适应限速 — 线程安全 + 暴露状态
# ═══════════════════════════════════════════════════════════════
class _RateLimiter:
    """线程安全的限速器，使用 Lock 保护共享状态（参考 CPython threading.Lock 最佳实践）"""
    def __init__(s): s._lock = threading.Lock(); s._t0 = 0.0; s._bo = 0.5; s._blocked = 0
    def throttle(s):
        with s._lock:
            d = random.uniform(0.5, max(2.0, s._bo))
            if (elapsed := time.time() - s._t0) < d: time.sleep(d - elapsed)
            s._t0 = time.time()
    def mark_blocked(s):
        with s._lock: s._bo = min(s._bo * 2, 60); s._blocked += 1
    def mark_ok(s):
        with s._lock: s._bo = max(s._bo * 0.9, 0.5)
    def status(s) -> dict:
        with s._lock: return {'current_backoff_seconds': round(s._bo, 1), 'blocked_count': s._blocked}

_limiter = _RateLimiter()
_throttle = _limiter.throttle
get_rate_limit_status = _limiter.status

# ═══════════════════════════════════════════════════════════════
# LRU 缓存 — no_cache + 统计
# ═══════════════════════════════════════════════════════════════
class _Cache:
    def __init__(s): s._d = OrderedDict(); s.hit = s.miss = s.skip = 0
    def get(s, k, nocache=False):
        if nocache: s.skip += 1; return None
        if k in s._d:
            t, v = s._d[k]
            if time.time()-t < CFG['ttl']: s._d.move_to_end(k); s.hit += 1; return v
            del s._d[k]
        s.miss += 1; return None
    def set(s, k, v, nocache=False):
        if nocache: return
        if len(s._d)>=CFG['cap']: s._d.popitem(last=False)
        s._d[k] = (time.time(), v); s._d.move_to_end(k)
    def stats(s) -> dict:
        return {'hit':s.hit, 'miss':s.miss, 'skip':s.skip, 'size':len(s._d), 'capacity':CFG['cap']}
_cache = _Cache()

# ═══════════════════════════════════════════════════════════════
# 文本工具
# ═══════════════════════════════════════════════════════════════
_RE_CHARSET = re.compile(r'charset=([\w-]+)')
_RE_SCRIPT  = re.compile(r'<(script|style|noscript)[^>]*>.*?</\1>', re.DOTALL | re.I)
_RE_TAG     = re.compile(r'<[^>]+>'); _RE_SPACE = re.compile(r'\s+')
_RE_BADCHAR = re.compile(r'[\u0000-\u0008\u000b\u000c\u000e-\u001f\ud800-\udfff]')
_RE_TITLE   = re.compile(r'<title[^>]*>(.*?)</title>', re.DOTALL | re.I)
def clean_text(h):
    h = _RE_SCRIPT.sub(' ', h); h = _RE_TAG.sub(' ', h)
    return _RE_SPACE.sub(' ', h).strip()
def sanitize(s): return _RE_BADCHAR.sub('', s)
def decode_body(raw, ct=''):
    cs = 'utf-8'
    if ct and (m := _RE_CHARSET.search(ct)): cs = m.group(1)
    try: return gzip.decompress(raw).decode(cs, errors='replace')
    except OSError: return raw.decode(cs, errors='replace')
def apply_length_limits(text: str, ml: int, si: int) -> str:
    if si >= len(text): return ""
    if ml <= 0: return text[si:]
    return text[si:min(si+ml, len(text))]

# ═══════════════════════════════════════════════════════════════
# HTML → Markdown 转换器（纯标准库，类似 Turndown）
# ═══════════════════════════════════════════════════════════════
_HEADING_TAGS = frozenset({'h1','h2','h3','h4','h5','h6'})
_VOID_TAGS   = frozenset({'br','hr','img','input','meta','link','area','base','col','embed','source','track','wbr'})
_BLOCK_TAGS  = frozenset({'p','div','section','article','header','footer','main','aside','nav','blockquote','pre',
                          'figure','figcaption','details','summary','fieldset','form','dl','dt','dd','address','hgroup'})

class _MdConverter(HTMLParser):
    def __init__(self):
        super().__init__()
        self._out = []; self._skip = 0
        self._list_depth = 0; self._list_counter = [0]
        self._link_url = None; self._link_text = []; self._in_link = False
        self._in_pre = False; self._pre_content = []
        self._table_rows = []; self._in_table = False
        self._in_tr = False; self._in_th = False; self._in_td = False
        self._row_cells = []

    def get_result(self) -> str:
        return re.sub(r'\n{4,}', '\n\n\n', ''.join(self._out)).strip()

    def _nl(self):
        if self._out and not self._out[-1].endswith('\n'): self._out.append('\n')

    def _flush_table(self):
        if not self._table_rows: return
        self._nl()
        cc = [len(r) for r in self._table_rows if r]
        if not cc: self._table_rows = []; return
        mc = max(cc)
        rows = ['| ' + ' | '.join(r + ['']*(mc-len(r))) + ' |' for r in self._table_rows]
        self._out.append(rows[0] + '\n| ' + ' | '.join(['---']*mc) + ' |\n')
        if len(rows) > 1: self._out.append('\n'.join(rows[1:]) + '\n')
        self._table_rows = []; self._out.append('\n')

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in ('script','style','noscript','head'): self._skip += 1; return
        if self._skip: return
        ad = dict(attrs)
        if tag == 'table': self._in_table = True; self._table_rows = []; self._nl(); return
        if self._in_table:
            if tag in ('thead','tbody','tfoot'): return
            if tag == 'tr': self._in_tr = True; self._row_cells = []; return
            if tag in ('th','td'): self._in_th = (tag=='th'); self._in_td = (tag=='td'); self._row_cells.append(''); return
        if tag in _VOID_TAGS:
            if tag == 'br': self._out.append('\n')
            elif tag == 'hr': self._nl(); self._out.append('\n---\n')
            elif tag == 'img':
                a,s = ad.get('alt',''), ad.get('src','')
                if a or s: self._out.append(f'![{_html.unescape(a)}]({s})')
        elif tag in _HEADING_TAGS: self._nl(); self._out.append('#'*int(tag[1])+' ')
        elif tag == 'a': self._in_link = True; self._link_url = ad.get('href',''); self._link_text = []
        elif tag in ('strong','b'): self._out.append('**')
        elif tag in ('em','i'): self._out.append('_')
        elif tag in ('del','s','strike'): self._out.append('~~')
        elif tag == 'code' and not self._in_pre: self._out.append('`')
        elif tag == 'pre': self._in_pre = True; self._pre_content = []; self._nl()
        elif tag == 'blockquote': self._nl()
        elif tag == 'ul': self._list_depth += 1; self._list_counter.append(0); self._nl()
        elif tag == 'ol': self._list_depth += 1; self._list_counter.append(1); self._nl()
        elif tag == 'li':
            indent = '  '*(self._list_depth-1)
            if self._list_counter[-1] > 0:
                self._out.append(f'{indent}{self._list_counter[-1]}. '); self._list_counter[-1] += 1
            else: self._out.append(f'{indent}- ')
        elif tag in _BLOCK_TAGS: self._nl()

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in ('script','style','noscript','head'):
            if self._skip: self._skip -= 1
            return
        if self._skip: return
        if self._in_table:
            if tag == 'th': self._in_th = False; return
            if tag == 'td': self._in_td = False; return
            if tag == 'tr':
                self._in_tr = False
                if self._row_cells: self._table_rows.append(self._row_cells)
                self._row_cells = []; return
            if tag in ('thead','tbody','tfoot'): return
            if tag == 'table': self._in_table = False; self._flush_table(); return
        if tag in _HEADING_TAGS: self._out.append('\n\n')
        elif tag == 'a':
            if self._in_link:
                t = ''.join(self._link_text).strip()
                if t and self._link_url: self._out.append(f'[{t}]({self._link_url})')
                elif self._link_url: self._out.append(f'<{self._link_url}>')
                self._in_link = False; self._link_url = None; self._link_text = []
        elif tag in ('strong','b'): self._out.append('**')
        elif tag in ('em','i'): self._out.append('_')
        elif tag in ('del','s','strike'): self._out.append('~~')
        elif tag == 'code' and not self._in_pre: self._out.append('`')
        elif tag == 'pre':
            self._in_pre = False
            self._out.append(f'\n```\n{"".join(self._pre_content).rstrip()}\n```\n\n')
        elif tag == 'blockquote': self._out.append('\n\n')
        elif tag == 'p': self._out.append('\n\n')
        elif tag in ('div','section','article','header','footer','main','aside','nav'): self._out.append('\n')
        elif tag == 'li': self._out.append('\n')
        elif tag == 'ul':
            self._list_depth -= 1; self._list_counter.pop()
            if self._list_depth == 0: self._nl()
        elif tag == 'ol':
            self._list_depth -= 1; self._list_counter.pop()
            if self._list_depth == 0: self._nl()

    def handle_data(self, data):
        if self._skip: return
        if self._in_pre: self._pre_content.append(data); return
        if self._in_table and (self._in_th or self._in_td):
            if self._row_cells:
                c = _html.unescape(data.strip())
                if c: self._row_cells[-1] += (' ' if self._row_cells[-1] else '') + c
            return
        t = data.strip()
        if not t: return
        t = _html.unescape(t)
        if self._in_link: self._link_text.append(t)
        else: self._out.append(t)

def html_to_markdown(html: str) -> str:
    body = sanitize(html)
    body = re.sub(r'<head[^>]*>.*?</head>', '', body, flags=re.DOTALL | re.I)
    body = _RE_SCRIPT.sub(' ', body)
    c = _MdConverter()
    try: c.feed(body)
    except Exception: pass
    return c.get_result()

# ═══════════════════════════════════════════════════════════════
# 文章正文提取（启发式评分，类似 Readability）
# ═══════════════════════════════════════════════════════════════
_RE_ARTICLE_CONTENT = re.compile(r'<(?:article|main|section)[^>]*>(.*?)</(?:article|main|section)>', re.DOTALL | re.I)
_RE_DIV_WITH_CLASS  = re.compile(r'<div[^>]*class="[^"]*(?:content|article|post|entry|main|body|text|story)[^"]*"[^>]*>(.*?)</div>', re.DOTALL | re.I)
_RE_NOISE_CLASS     = re.compile(r'<(?:div|nav|aside|footer|header)[^>]*class="[^"]*(?:nav|menu|sidebar|footer|header|comment|ad|advert|banner|social|share|related|recommend|widget|popup|modal)[^"]*"[^>]*>.*?</(?:div|nav|aside|footer|header)>', re.DOTALL | re.I)
_RE_NOISE_TAG       = re.compile(r'<(?:nav|aside|footer|header)[^>]*>.*?</(?:nav|aside|footer|header)>', re.DOTALL | re.I)

def _score_text_block(text: str) -> float:
    if not text or len(text) < 80: return 0.0
    p = len(re.findall(r'<p[\s>]', text))
    h = len(re.findall(r'<h[1-6][\s>]', text))
    plain = re.sub(r'<[^>]+>', '', text).strip()
    return min(p/5,3.0)*10 + min(h/3,2.0)*15 + (len(plain)/max(len(text),1))*30 + min(len(plain)/500,5.0)*5

def extract_readable(html: str) -> str:
    body = sanitize(html)
    body = re.sub(r'<head[^>]*>.*?</head>', '', body, flags=re.DOTALL | re.I)
    body = _RE_SCRIPT.sub(' ', body)
    for pat,desc in [(_RE_ARTICLE_CONTENT,'article'), (_RE_DIV_WITH_CLASS,'div.content')]:
        ms = pat.findall(body)
        if ms:
            best = max(ms, key=_score_text_block)
            if _score_text_block(best) > 10:
                log.debug(f'  正文提取: {desc} (score={_score_text_block(best):.1f})')
                return best
    cleaned = _RE_NOISE_CLASS.sub(' ', body)
    cleaned = _RE_NOISE_TAG.sub(' ', cleaned)
    if _score_text_block(cleaned) < _score_text_block(body): cleaned = body
    log.debug(f'  正文提取: 去噪 (score={_score_text_block(cleaned):.1f})')
    return cleaned

# ═══════════════════════════════════════════════════════════════
# Bing 解析器 — Web / Images / News / Videos
# ═══════════════════════════════════════════════════════════════
class _BingParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.results = []; self._skip = 0
        self._in_block = False; self._url = None; self._title = []; self._snippet = []; self._in_h2 = 0
    def handle_starttag(self, tag, attrs):
        if tag in ('script','style','noscript','head'): self._skip += 1; return
        if self._skip: return
        ad = dict(attrs); cls = ad.get('class','')
        if tag == 'li' and any(k in cls for k in ('b_algo','b_ans','b_rs','b_ad')):
            if not self._in_block: self._in_block = True; self._url = None; self._title = []; self._snippet = []
            return
        if not self._in_block: return
        if tag == 'a' and (href:=ad.get('href','')).startswith('http') and not self._url: self._url = href
        if tag == 'h2': self._in_h2 += 1
        if tag in ('h3','h4') and not self._in_h2: self._in_h2 += 1
    def handle_endtag(self, tag):
        if tag in ('script','style','noscript','head'):
            if self._skip: self._skip -= 1
            return
        if self._skip: return
        if tag == 'li' and self._in_block:
            t = clean_text(' '.join(self._title)); s = clean_text(' '.join(self._snippet)) if self._snippet else ''
            if t and self._url:
                self.results.append({'title':_html.unescape(t),'url':_html.unescape(self._url),
                                     'snippet':_html.unescape(s),'type':'web'})
            self._in_block = False; return
        if not self._in_block: return
        if tag in ('h2','h3','h4') and self._in_h2: self._in_h2 -= 1
    def handle_data(self, data):
        if self._skip or not self._in_block: return
        if t := data.strip(): (self._title if self._in_h2 else self._snippet).append(t)

_RE_R_ITEM = re.compile(r'<li[^>]*class="[^"]*b_(?:algo|ans|rs|_ad)[^"]*"[^>]*>(.*?)</li>', re.DOTALL)
_RE_R_H2A  = re.compile(r'<(?:h2|h3|h4)[^>]*>\s*<a[^>]*href="(https?://[^"]+)"[^>]*>(.*?)</a>', re.DOTALL)
_RE_R_AH2  = re.compile(r'<a[^>]*href="(https?://[^"]+)"[^>]*>\s*<(?:h2|h3|h4)[^>]*>(.*?)</(?:h2|h3|h4)>', re.DOTALL)
_RE_R_SNIP = re.compile(r'<(?:p|div)[^>]*>(.*?)</(?:p|div)>', re.DOTALL)
_SELF_DOMAINS = frozenset({'bing.com', 'microsoft.com', 'www.bing.com', 'www.microsoft.com'})

def _is_self_domain(url: str) -> bool:
    """基于 hostname 精确判断 URL 是否为搜索引擎自身域名，避免子串误判"""
    try:
        host = (urlparse(url).hostname or '').lower()
        # 精确匹配：hostname == domain 或以 .domain 结尾（覆盖子域）
        return host in _SELF_DOMAINS or any(host.endswith('.' + d) for d in ('bing.com', 'microsoft.com'))
    except Exception:
        return True  # 无法解析则保守拒绝

def _parse_regex(html, count):
    body = re.sub(r'<head[^>]*>.*?</head>', '', html, flags=re.DOTALL|re.I); body = _RE_SCRIPT.sub(' ', body)
    results, seen = [], set()
    for m in _RE_R_ITEM.finditer(body):
        if len(results) >= count: break
        chunk = m.group(1); link = _RE_R_H2A.search(chunk) or _RE_R_AH2.search(chunk)
        if not link: continue
        u, t = link.group(1), clean_text(link.group(2))
        if not t or not u or u in seen or _is_self_domain(u): continue
        seen.add(u); sn = _RE_R_SNIP.search(chunk)
        results.append({'title':_html.unescape(t),'url':_html.unescape(u),
                        'snippet':_html.unescape(clean_text(sn.group(1) or '') if sn else ''),'type':'web'})
    return results

def _parse_bing(html, count):
    body = sanitize(html); p = _BingParser()
    try: p.feed(body)
    except Exception as e: log.debug(f'HTMLParser err: {e}')
    if p.results:
        seen, out = set(), []
        for r in p.results:
            u = r['url']
            if u in seen or _is_self_domain(u): continue
            seen.add(u); out.append(_enrich_result(r))
            if len(out) >= count: break
        return out
    return [_enrich_result(r) for r in _parse_regex(html, count)]

def _enrich_result(r: dict) -> dict:
    try:
        p = urlparse(r.get('url',''))
        hostname = p.hostname or ''
        if hostname.startswith('www.'): hostname = hostname[4:]
        r['site_name'] = hostname
    except Exception: r['site_name'] = ''
    r.setdefault('type', 'web')
    return r

# --- 图片搜索解析器 ---
_RE_IMG_SRC  = re.compile(r'<img[^>]*src="(https?://[^"]+)"', re.I)
_RE_IMG_A    = re.compile(r'<a[^>]*href="(https?://[^"]+)"', re.I)
_RE_IMG_ALT  = re.compile(r'alt="([^"]*)"', re.I)
_RE_IMG_DIM  = re.compile(r'(?:width|height)=["\']?(\d+)', re.I)

def _parse_bing_images(html: str, count: int) -> list:
    body = sanitize(html)
    body = re.sub(r'<head[^>]*>.*?</head>', '', body, flags=re.DOTALL | re.I)
    body = _RE_SCRIPT.sub(' ', body)
    results, seen = [], set()
    img_blocks = re.findall(r'<li[^>]*class="[^"]*img_cont[^"]*"[^>]*>(.*?)</li>', body, re.DOTALL)
    if not img_blocks:
        img_blocks = re.findall(r'<div[^>]*class="[^"]*imgpt[^"]*"[^>]*>(.*?)</li>', body, re.DOTALL)
    for block in img_blocks:
        if len(results) >= count: break
        img_match = _RE_IMG_SRC.search(block)
        if not img_match: continue
        img_url = img_match.group(1)
        if img_url in seen: continue
        seen.add(img_url)
        alt_match = _RE_IMG_ALT.search(block)
        title = _html.unescape(alt_match.group(1)) if alt_match else ''
        a_match = _RE_IMG_A.search(block)
        page_url = a_match.group(1) if a_match else img_url
        width = height = None
        for m in _RE_IMG_DIM.finditer(block):
            dim = int(m.group(1))
            if 'width' in m.group(0).lower(): width = dim
            else: height = dim
        result = {'title':title, 'url':page_url, 'image_url':img_url, 'type':'image',
                  'width':width, 'height':height, 'snippet':title}
        results.append(_enrich_result(result))
    if not results:
        for m in _RE_IMG_SRC.finditer(body):
            if len(results) >= count: break
            img_url = m.group(1)
            if img_url in seen or _is_self_domain(img_url): continue
            if re.search(r'(icon|avatar|logo|favicon)', img_url, re.I): continue
            seen.add(img_url)
            results.append(_enrich_result({'title':'','url':img_url,'image_url':img_url,'type':'image','snippet':''}))
    return results

# --- 新闻搜索解析器 ---
_RE_NEWS_ITEM = re.compile(r'<(?:div|li)[^>]*class="[^"]*(?:news-card|newsitem|b_ans)[^"]*"[^>]*>(.*?)</(?:div|li)>', re.DOTALL | re.I)
_RE_NEWS_A   = re.compile(r'<a[^>]*href="(https?://[^"]+)"[^>]*>(.*?)</a>', re.DOTALL)
_RE_NEWS_DATE = re.compile(r'(?:datetime|data-date)=["\']?([^"\'>\s]+)', re.I)
_RE_NEWS_SOURCE = re.compile(r'class="[^"]*source[^"]*"[^>]*>(.*?)</(?:span|div|a)>', re.DOTALL | re.I)

def _parse_bing_news(html: str, count: int) -> list:
    body = sanitize(html)
    body = re.sub(r'<head[^>]*>.*?</head>', '', body, flags=re.DOTALL | re.I)
    body = _RE_SCRIPT.sub(' ', body)
    results, seen = [], set()
    parsed = _parse_bing(html, count * 2)
    for r in parsed:
        if len(results) >= count: break
        u = r.get('url','')
        if u and u not in seen: seen.add(u); r['type'] = 'news'; results.append(r)
    if not results:
        for block in _RE_NEWS_ITEM.findall(body):
            if len(results) >= count: break
            a_match = _RE_NEWS_A.search(block)
            if not a_match: continue
            u, t = a_match.group(1), clean_text(a_match.group(2))
            if not t or not u or u in seen or _is_self_domain(u): continue
            seen.add(u)
            date_match = _RE_NEWS_DATE.search(block)
            source_match = _RE_NEWS_SOURCE.search(block)
            r = {'title':_html.unescape(t), 'url':_html.unescape(u), 'snippet':t, 'type':'news',
                 'published_date':date_match.group(1) if date_match else None,
                 'source':clean_text(source_match.group(1)) if source_match else None}
            results.append(_enrich_result(r))
    return results

# --- 视频搜索解析器 ---
_RE_VIDEO_ITEM = re.compile(r'<(?:div|li)[^>]*class="[^"]*(?:mc_vtvc|dg_b)[^"]*"[^>]*>(.*?)</(?:div|li)>', re.DOTALL | re.I)
_RE_VIDEO_THUMB = re.compile(r'<img[^>]*src="(https?://[^"]+)"[^>]*>', re.I)
_RE_VIDEO_DUR = re.compile(r'(?:duration|dur|时间)[:\s]*(\d+:\d+)', re.I)
_RE_VIDEO_VIEWS = re.compile(r'(\d+[\d,.]*[万KMB]?\s*(?:views|次观看|播放))', re.I)

def _parse_bing_videos(html: str, count: int) -> list:
    body = sanitize(html)
    body = re.sub(r'<head[^>]*>.*?</head>', '', body, flags=re.DOTALL | re.I)
    body = _RE_SCRIPT.sub(' ', body)
    results, seen = [], set()
    for block in _RE_VIDEO_ITEM.findall(body):
        if len(results) >= count: break
        a_match = _RE_R_H2A.search(block) or _RE_R_AH2.search(block) or _RE_NEWS_A.search(block)
        if not a_match: continue
        u, t = a_match.group(1), clean_text(a_match.group(2))
        if not t or not u or u in seen or _is_self_domain(u): continue
        seen.add(u)
        thumb_match = _RE_VIDEO_THUMB.search(block)
        dur_match = _RE_VIDEO_DUR.search(block)
        views_match = _RE_VIDEO_VIEWS.search(block)
        r = {'title':_html.unescape(t), 'url':_html.unescape(u), 'snippet':t, 'type':'video',
             'thumbnail_url':thumb_match.group(1) if thumb_match else None,
             'duration':dur_match.group(1) if dur_match else None,
             'view_count':views_match.group(1).strip() if views_match else None}
        results.append(_enrich_result(r))
    return results

# --- 拼写建议 / 相关搜索 / 总数估算 ---
_RE_SPELL_SUGGEST = re.compile(r'(?:sp_recourse|sp_requery|splink).*?>(.*?)</(?:a|span)>', re.DOTALL | re.I)
_RE_RELATED      = re.compile(r'<(?:li|a)[^>]*class="[^"]*b_rs[^"]*"[^>]*>\s*<a[^>]*href="[^"]*"[^>]*>(.*?)</a>', re.DOTALL | re.I)
_RE_TOTAL_COUNT  = re.compile(r'([\d,]+)\s*(?:个?结果|results|件)', re.I)

def _extract_meta(html: str) -> dict:
    body = html[:64000]; meta = {}
    spell = _RE_SPELL_SUGGEST.findall(body)
    if spell: meta['spellcheck_suggestion'] = _html.unescape(clean_text(spell[0]))
    related = _RE_RELATED.findall(body)
    if related: meta['related_searches'] = [_html.unescape(clean_text(r)) for r in related[:8]]
    tc = _RE_TOTAL_COUNT.search(body)
    if tc:
        try: meta['estimated_total_results'] = int(tc.group(1).replace(',', ''))
        except ValueError: pass
    return meta

_RE_BLOCKED = re.compile(r'captcha|robot|verify|denied|blocked|unusual.traffic|are.you.a.human|access.denied|rate.limit|challenge|\u9a8c\u8bc1|\u62e6\u622a|\u4eba\u673a|\u8eab\u4efd', re.I)
def _is_blocked(html, status=None): return (status and status in (403,429,503)) or bool(_RE_BLOCKED.search(html[:64000]))

# ═══════════════════════════════════════════════════════════════
# HTTP 引擎 — 白名单过滤 custom_headers
# ═══════════════════════════════════════════════════════════════
def _filter_headers(custom_headers: Optional[dict]) -> dict:
    if not custom_headers: return {}
    return {k: v for k, v in custom_headers.items() if k in ALLOWED_CUSTOM_HEADERS}

def fetch(url, timeout=None, referer=None, max_body=None, verify=None, custom_headers=None):
    timeout = timeout or CFG['timeout']; max_body = max_body or CFG['max_response']
    if verify is None: verify = _is_self_domain(url)
    validate_url(url); _throttle(); errs = []
    tid = _trace_id(); t0 = time.time()
    log.debug(f'[{tid}] fetch: {url[:120]}')
    for i in range(CFG['retry']+1):
        hdrs = dict(BASE_HDR, **{'User-Agent': random.choice(UA)})
        if referer: hdrs['Referer'] = referer
        filtered = _filter_headers(custom_headers)
        if filtered: hdrs.update(filtered)
        opener = _make_opener(verify)
        try:
            resp = opener.open(Request(url, headers=hdrs), timeout=timeout)
            if resp.geturl() != url: validate_url(resp.geturl())
            cl = resp.headers.get('Content-Length')
            if cl:
                try:
                    if int(cl) > max_body: raise ValueError(f'Content-Length {cl} 超限')
                except ValueError: raise ValueError(f'Content-Length {cl} 超限')
            chunks, received = [], 0
            while True:
                chunk = resp.read(8192)
                if not chunk: break
                received += len(chunk)
                if received > max_body: raise ValueError(f'响应体超 {max_body}B (已读 {received}B)')
                chunks.append(chunk)
            result = sanitize(decode_body(b''.join(chunks), resp.headers.get('Content-Type','')))
            _log_timing(tid, 'fetch OK', t0)
            return result
        except ValueError: raise
        except (HTTPError,URLError,OSError) as e:
            errs.append(f'{type(e).__name__}: {str(e)[:80]}')
            log.debug(f'[{tid}] 重试 {i+1}: {e}')
            if i < CFG['retry']: time.sleep(i+1)
    log.warning(f'[{tid}] fetch FAIL after {CFG["retry"]+1} attempts')
    raise Exception('; '.join(errs[-3:]))

# ═══════════════════════════════════════════════════════════════
# Bing 搜索 — 参数构建 + 多类型 + 双语
# ═══════════════════════════════════════════════════════════════

FRESHNESS_MAP = {
    'day':'ex1:"ez1"','week':'ex1:"ez2"','month':'ex1:"ez3"','year':'ex1:"ez4"',
    'pd':'ex1:"ez1"','pw':'ex1:"ez2"','pm':'ex1:"ez3"','py':'ex1:"ez4"',
}
SEARCH_URLS = {
    'web':'https://www.bing.com/search', 'images':'https://www.bing.com/images/search',
    'news':'https://www.bing.com/news/search', 'videos':'https://www.bing.com/videos/search',
}
SEARCH_REFERERS = {
    'web':'https://www.bing.com/', 'images':'https://www.bing.com/images/',
    'news':'https://www.bing.com/news/', 'videos':'https://www.bing.com/videos/',
}
SEARCH_PARSERS = {
    'web':_parse_bing, 'images':_parse_bing_images,
    'news':_parse_bing_news, 'videos':_parse_bing_videos,
}

def _build_bing_params(query: str, count: int, lang: str = 'zh-Hans',
                       freshness: Optional[str] = None,
                       safesearch: Optional[str] = None,
                       offset: int = 0) -> str:
    params = {'q':query, 'setlang':lang, 'count':min(count,50), 'mkt':lang}
    if offset > 0: params['first'] = str(offset + 1)
    if freshness:
        if freshness in FRESHNESS_MAP:
            params['filters'] = FRESHNESS_MAP[freshness]
        elif re.match(r'^\d{4}-\d{2}-\d{2}to\d{4}-\d{2}-\d{2}$', freshness):
            params['filters'] = f'cdr:1,cd_min:{freshness[:10]},cd_max:{freshness[11:21]}'
    if safesearch and safesearch in ('off','moderate','strict'):
        params['adlt'] = safesearch
    return urlencode(params)

def _search_bing_lang(query, count, lang='zh-Hans', freshness=None,
                      safesearch=None, offset=0, search_type='web'):
    p = _build_bing_params(query, count, lang, freshness, safesearch, offset)
    url = f'{SEARCH_URLS.get(search_type, SEARCH_URLS["web"])}?{p}'
    referer = SEARCH_REFERERS.get(search_type, SEARCH_REFERERS['web'])
    try:
        html = fetch(url, referer=referer, verify=True)
    except Exception as e:
        log.warning(f'  搜索失败({lang}/{search_type}): {e}')
        return [], {}
    if _is_blocked(html):
        _limiter.mark_blocked()
        log.warning(f'  反爬, 退避 {_limiter._bo:.0f}s (累计被封:{_limiter._blocked}次)')
        return [], {}
    _limiter.mark_ok()
    meta = _extract_meta(html) if search_type == 'web' else {}
    parser = SEARCH_PARSERS.get(search_type, _parse_bing)
    return parser(html, count), meta

def search_bing(query, count=15, freshness=None, safesearch=None, offset=0,
                search_type='web', no_cache=False):
    cache_key = f'{search_type}\x00{query}\x00{count}\x00{freshness}\x00{safesearch}\x00{offset}'
    if not no_cache and (c := _cache.get(cache_key)): return c
    log.info(f'搜索({search_type}): "{query[:60]}" (x{count})')
    all_r, seen, all_meta = [], set(), {}
    langs = [('zh-Hans','CN'), ('en','EN')] if search_type == 'web' else [('zh-Hans','CN')]
    for lang, lb in langs:
        results, meta = _search_bing_lang(query, count, lang, freshness, safesearch, offset, search_type)
        if meta: all_meta.update(meta)
        for r in results:
            if r['url'] not in seen: seen.add(r['url']); all_r.append(r)
        log.info(f'  {lb}: => total {len(all_r)}')
        if len(all_r) >= count: break
    if search_type != 'web' and len(all_r) < count and len(langs) == 1:
        results2, meta2 = _search_bing_lang(query, count, 'en', freshness, safesearch, offset, search_type)
        if meta2: all_meta.update(meta2)
        for r in results2:
            if r['url'] not in seen and len(all_r) < count: seen.add(r['url']); all_r.append(r)
        log.info(f'  EN(fallback): => total {len(all_r)}')
    data = {'query':query, 'engine':'bing', 'type':search_type, 'count':len(all_r[:count]),
            'results':all_r[:count], '_rate_limit':get_rate_limit_status()}
    if all_meta: data['meta'] = all_meta
    if all_r: _cache.set(cache_key, data, nocache=no_cache)
    return data

# ═══════════════════════════════════════════════════════════════
# 网页抓取
# ═══════════════════════════════════════════════════════════════
def fetch_page(url, max_len=5000, start_index=0, custom_headers=None, no_cache=False):
    cache_key = f'F\x00{url}\x00{max_len}\x00{start_index}'
    if not no_cache and (c := _cache.get(cache_key)): return c
    u = url.strip()
    if not u.startswith(('http://','https://')): u = 'https://'+u
    validate_url(u)
    log.info(f'抓取: {u[:80]}')
    try: html = fetch(u, verify=False, custom_headers=custom_headers)
    except Exception as e: log.warning(f'  失败: {e}'); raise
    try:
        parsed = json.loads(html)
        if isinstance(parsed, (dict, list)):
            fmt = json.dumps(parsed, indent=2, ensure_ascii=False)
            fmt = apply_length_limits(fmt, max_len, start_index)
            data = {'url':u, 'title':'', 'format':'json', 'length':len(fmt), 'content':fmt,
                    '_rate_limit':get_rate_limit_status()}
            _cache.set(cache_key, data, nocache=no_cache)
            log.info(f'  JSON: {len(fmt)} 字符'); return data
    except (json.JSONDecodeError, ValueError): pass
    title = _html.unescape(clean_text(m.group(1))) if (m:=_RE_TITLE.search(html)) else ''
    text = clean_text(html); text = apply_length_limits(text, max_len, start_index)
    data = {'url':u, 'title':title, 'format':'text', 'length':len(text), 'content':text,
            '_rate_limit':get_rate_limit_status()}
    _cache.set(cache_key, data, nocache=no_cache)
    log.info(f'  text: {len(text)} 字符'); return data

def fetch_markdown(url, max_len=5000, start_index=0, custom_headers=None, readable=False, no_cache=False):
    cache_key = f'M\x00{url}\x00{max_len}\x00{start_index}\x00{readable}'
    if not no_cache and (c := _cache.get(cache_key)): return c
    u = url.strip()
    if not u.startswith(('http://','https://')): u = 'https://'+u
    validate_url(u)
    log.info(f'抓取({"Readable+MD" if readable else "MD"}): {u[:80]}')
    try: html = fetch(u, verify=False, custom_headers=custom_headers)
    except Exception as e: log.warning(f'  失败: {e}'); raise
    title = _html.unescape(clean_text(m.group(1))) if (m:=_RE_TITLE.search(html)) else ''
    md = html_to_markdown(extract_readable(html) if readable else html)
    md = apply_length_limits(md, max_len, start_index)
    data = {'url':u, 'title':title, 'format':'markdown',
            'mode':'readable' if readable else 'full', 'length':len(md), 'content':md,
            '_rate_limit':get_rate_limit_status()}
    _cache.set(cache_key, data, nocache=no_cache)
    log.info(f'  markdown: {len(md)} 字符 ({data["mode"]})'); return data

# ═══════════════════════════════════════════════════════════════
# MCP — Tool定义 + Schema + 请求分发
# ═══════════════════════════════════════════════════════════════

ALL_TOOLS = {
    'search_web': {
        'description': '搜索网络（Bing 搜索引擎），返回标题、URL 和摘要。支持时间过滤、安全搜索、分页。',
        'inputSchema': {'type':'object', 'properties':{
            'query':{'type':'string','description':'搜索关键词（最长200字符）','maxLength':200},
            'count':{'type':'integer','description':'结果数量（1-50）','default':15,'minimum':1,'maximum':50},
            'freshness':{'type':'string','description':'时间过滤: day(24h)/week(7d)/month(31d)/year(365d) 或 YYYY-MM-DDtoYYYY-MM-DD',
                         'enum':['day','week','month','year','pd','pw','pm','py']},
            'safesearch':{'type':'string','description':'安全搜索: off/moderate/strict','enum':['off','moderate','strict'],'default':'moderate'},
            'offset':{'type':'integer','description':'分页偏移量','default':0,'minimum':0,'maximum':100},
            'country':{'type':'string','description':'搜索地区代码（如 US, CN, JP）'},
            'search_lang':{'type':'string','description':'搜索语言（如 zh-Hans, en）','default':'zh-Hans'},
            'no_cache':{'type':'boolean','description':'跳过缓存','default':False},
        }, 'required':['query']},
    },
    'search_images': {
        'description': '搜索图片（Bing 图片搜索），返回图片URL、尺寸、来源页面。',
        'inputSchema': {'type':'object', 'properties':{
            'query':{'type':'string','description':'搜索关键词','maxLength':200},
            'count':{'type':'integer','description':'结果数量（1-50）','default':20,'minimum':1,'maximum':50},
            'safesearch':{'type':'string','description':'安全搜索: off/strict','enum':['off','strict'],'default':'strict'},
            'freshness':{'type':'string','description':'时间过滤','enum':['day','week','month','year']},
            'no_cache':{'type':'boolean','description':'跳过缓存','default':False},
        }, 'required':['query']},
    },
    'search_news': {
        'description': '搜索新闻（Bing 新闻搜索），返回标题、URL、摘要、发布日期、来源。',
        'inputSchema': {'type':'object', 'properties':{
            'query':{'type':'string','description':'搜索关键词','maxLength':200},
            'count':{'type':'integer','description':'结果数量（1-30）','default':15,'minimum':1,'maximum':30},
            'freshness':{'type':'string','description':'时间过滤: day/week/month，默认24h','enum':['day','week','month'],'default':'day'},
            'safesearch':{'type':'string','description':'安全搜索','enum':['off','moderate','strict'],'default':'moderate'},
            'country':{'type':'string','description':'搜索地区代码'},
            'no_cache':{'type':'boolean','description':'跳过缓存','default':False},
        }, 'required':['query']},
    },
    'search_videos': {
        'description': '搜索视频（Bing 视频搜索），返回标题、URL、缩略图、时长、播放量。',
        'inputSchema': {'type':'object', 'properties':{
            'query':{'type':'string','description':'搜索关键词','maxLength':200},
            'count':{'type':'integer','description':'结果数量（1-30）','default':15,'minimum':1,'maximum':30},
            'freshness':{'type':'string','description':'时间过滤','enum':['day','week','month','year']},
            'safesearch':{'type':'string','description':'安全搜索','enum':['off','moderate','strict'],'default':'moderate'},
            'no_cache':{'type':'boolean','description':'跳过缓存','default':False},
        }, 'required':['query']},
    },
    'fetch_webpage': {
        'description': '获取指定网页内容。自动识别 JSON 响应并格式化输出；否则返回纯文本。',
        'inputSchema': {'type':'object', 'properties':{
            'url':{'type':'string','description':'网页URL','maxLength':2048},
            'max_length':{'type':'integer','description':'最大字符数（0=无限制）','default':5000,'minimum':0,'maximum':50000},
            'start_index':{'type':'integer','description':'起始索引（分页）','default':0,'minimum':0},
            'headers':{'type':'object','description':'自定义请求头（受白名单限制）'},
            'no_cache':{'type':'boolean','description':'跳过缓存','default':False},
        }, 'required':['url']},
    },
    'fetch_markdown': {
        'description': '获取网页并转为 Markdown。保留标题/列表/链接/代码/表格结构。默认提取正文（去广告/导航）。',
        'inputSchema': {'type':'object', 'properties':{
            'url':{'type':'string','description':'网页URL','maxLength':2048},
            'max_length':{'type':'integer','description':'最大字符数','default':5000,'minimum':0,'maximum':50000},
            'start_index':{'type':'integer','description':'起始索引','default':0,'minimum':0},
            'headers':{'type':'object','description':'自定义请求头（受白名单限制）'},
            'readable':{'type':'boolean','description':'提取正文主体','default':True},
            'no_cache':{'type':'boolean','description':'跳过缓存','default':False},
        }, 'required':['url']},
    },
    'cache_stats': {
        'description': '查看缓存统计信息（命中率、大小等）。',
        'inputSchema': {'type':'object', 'properties':{}, 'required':[]},
    },
}

TOOLS = {k: v for k, v in ALL_TOOLS.items() if is_tool_permitted(k)}

def _jr(mid, r): return {'jsonrpc':'2.0','id':mid,'result':r}
def _je(mid, code, msg): return {'jsonrpc':'2.0','id':mid,'error':{'code':code,'message':msg}}
def _tr(data): return {'content':[{'type':'text','text':json.dumps(data, ensure_ascii=False, default=str)}]}
def _tr_error(msg: str) -> dict:
    return {'content':[{'type':'text','text':json.dumps({'error':msg}, ensure_ascii=False)}], 'isError':True}

def _parse_headers(h):
    if not h: return None
    if isinstance(h, dict): return _filter_headers(h)
    if isinstance(h, str):
        try:
            parsed = json.loads(h)
            return _filter_headers(parsed) if isinstance(parsed, dict) else None
        except json.JSONDecodeError: raise ValueError('headers 格式错误')
    raise ValueError('headers 应为字典')

# 搜索类型 → 处理函数映射
_SEARCH_TYPES = {'search_web':'web', 'search_images':'images', 'search_news':'news', 'search_videos':'videos'}

# Schema 查找 — 从 inputSchema 的 properties 自动推导
def _schema_from_tool(name: str) -> dict:
    props = ALL_TOOLS.get(name, {}).get('inputSchema', {}).get('properties', {})
    result = {}
    type_map = {'string':'str', 'integer':'int', 'boolean':'bool', 'object':'str'}
    for k, v in props.items():
        rules = {'type': type_map.get(v.get('type',''), 'str'),
                 'required': k in (ALL_TOOLS[name]['inputSchema'].get('required', [])),
                 'default': v.get('default')}
        if 'minimum' in v: rules['min'] = v['minimum']
        if 'maximum' in v: rules['max'] = v['maximum']
        if 'maxLength' in v: rules['max_len'] = v['maxLength']
        if 'enum' in v: rules['enum'] = v['enum']
        result[k] = rules
    return result

def dispatch(line):
    tid = _trace_id(); t_start = time.time()
    try: msg = json.loads(line)
    except json.JSONDecodeError: return None
    mid, method, params = msg.get('id'), msg.get('method',''), msg.get('params',{})
    if method == 'initialize':
        ci = params.get('clientInfo',{})
        log.info(f'[{tid}] 连接: {ci.get("name","?")} v{ci.get("version","?")}')
        return _jr(mid, {'protocolVersion':'2024-11-05','capabilities':{'tools':{}},
                         'serverInfo':{'name':'web-search','version':'3.1.0'}})
    if method in ('notifications/initialized','notifications/cancelled'): return None
    if method == 'shutdown': return _jr(mid, None)
    if method == 'exit': raise SystemExit()
    if method == 'tools/list':
        return _jr(mid, {'tools':[{'name':k,**v} for k,v in TOOLS.items()]})
    if method == 'tools/call':
        name, args = params.get('name',''), params.get('arguments',{})
        log.info(f'[{tid}] 调用: {name}')
        try:
            if search_type := _SEARCH_TYPES.get(name):
                v = validate_args(args, _schema_from_tool(name))
                result = search_bing(v['query'], v.get('count', 15),
                                     freshness=v.get('freshness'),
                                     safesearch=v.get('safesearch'),
                                     offset=v.get('offset', 0),
                                     search_type=search_type,
                                     no_cache=v.get('no_cache', False))
                _log_timing(tid, name, t_start)
                return _jr(mid, _tr(result))
            if name == 'fetch_webpage':
                v = validate_args(args, _schema_from_tool(name))
                result = fetch_page(v['url'], v.get('max_length', 5000), v.get('start_index', 0),
                                    _parse_headers(v.get('headers')), no_cache=v.get('no_cache', False))
                _log_timing(tid, name, t_start)
                return _jr(mid, _tr(result))
            if name == 'fetch_markdown':
                v = validate_args(args, _schema_from_tool(name))
                result = fetch_markdown(v['url'], v.get('max_length', 5000), v.get('start_index', 0),
                                        _parse_headers(v.get('headers')),
                                        readable=v.get('readable', True),
                                        no_cache=v.get('no_cache', False))
                _log_timing(tid, name, t_start)
                return _jr(mid, _tr(result))
            if name == 'cache_stats':
                result = _cache.stats(); result['rate_limit'] = get_rate_limit_status()
                _log_timing(tid, name, t_start)
                return _jr(mid, _tr(result))
            return _je(mid, -32601, f'未知工具: {name}')
        except Exception as e:
            log.error(f'[{tid}] 错误: {e}')
            return _jr(mid, _tr_error(str(e)))
    if method == 'ping': return _jr(mid, {})
    return None

# ═══════════════════════════════════════════════════════════════
# 入口 — STDIO / HTTP 双模式
# ═══════════════════════════════════════════════════════════════
def _run_stdio():
    socket.setdefaulttimeout(30)
    li = f'{CFG["default_limit"]}字符' if CFG['default_limit']>0 else '无限制'
    log.info(f'启动 web-search v3.1.0 (STDIO) | 代理:{CFG["proxy"] or "无"} | TTL:{CFG["ttl"]}s | 缓存:{CFG["cap"]} | 默认:{li}')
    log.info(f'工具({len(TOOLS)}): {", ".join(TOOLS.keys())}')
    if ENABLED_TOOLS: log.info(f'启禁: 白名单 {ENABLED_TOOLS}')
    if DISABLED_TOOLS: log.info(f'启禁: 黑名单 {DISABLED_TOOLS}')
    for line in sys.stdin:
        if not (line:=line.strip()): continue
        try:
            if resp := dispatch(line):
                sys.stdout.buffer.write(json.dumps(resp, ensure_ascii=False, default=str).encode('utf-8')+b'\n')
                sys.stdout.buffer.flush()
        except (EOFError, KeyboardInterrupt): break
        except Exception as e: log.error(f'致命: {e}'); break
    log.info(f'退出 | 缓存 命中:{_cache.hit} 未命中:{_cache.miss} 跳过:{_cache.skip} 大小:{len(_cache._d)}')

def _run_http():
    import threading
    from http.server import HTTPServer, BaseHTTPRequestHandler
    _lock = threading.Lock()

    class MCPHTTPHandler(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _norm_path(self):
            if self.path.startswith('//'):
                self.path = '/' + self.path.lstrip('/')
        def do_POST(self):
            tid = _trace_id()
            try:
                cl = int(self.headers.get('Content-Length', 0))
                if cl == 0: self.send_error(400, 'Empty body'); return
                body = self.rfile.read(cl).decode('utf-8')
                log.debug(f'[{tid}] HTTP POST {len(body)}B')
                with _lock: resp = dispatch(body)
                if resp:
                    rb = json.dumps(resp, ensure_ascii=False, default=str).encode('utf-8')
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(rb)))
                    if CFG['stateless']: self.send_header('Mcp-Session-Id', 'stateless')
                    self.end_headers(); self.wfile.write(rb)
                else: self.send_response(204); self.end_headers()
            except Exception as e:
                log.error(f'[{tid}] HTTP error: {e}')
                self.send_error(500, _html.escape(str(e)[:200]))
        def do_GET(self):
            self._norm_path()
            if self.path in ('/ping', '/'):
                msg = json.dumps({'status':'ok', 'service':'web-search', 'version':'3.1.0',
                                  'tools':list(TOOLS.keys()), 'cache':_cache.stats()}, ensure_ascii=False)
                self.send_response(200); self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(msg))); self.end_headers()
                self.wfile.write(msg.encode('utf-8'))
            else: self.send_error(404, 'Not Found')

    server = HTTPServer((CFG['http_host'], CFG['http_port']), MCPHTTPHandler)
    log.info(f'启动 web-search v3.1.0 (HTTP) | {CFG["http_host"]}:{CFG["http_port"]} | stateless:{CFG["stateless"]}')
    log.info(f'工具({len(TOOLS)}): {", ".join(TOOLS.keys())}')
    try: server.serve_forever()
    except KeyboardInterrupt: server.shutdown(); log.info('HTTP服务已停止')

def main():
    import argparse
    parser = argparse.ArgumentParser(description='web-search v3.1.0 MCP Server')
    parser.add_argument('--transport', choices=['stdio','http'], default=CFG['transport'])
    parser.add_argument('--port', type=int, default=CFG['http_port'])
    parser.add_argument('--host', type=str, default=CFG['http_host'])
    parser.add_argument('--stateless', action='store_true', default=CFG['stateless'])
    args, _ = parser.parse_known_args()
    CFG.update({'transport':args.transport, 'http_port':args.port,
                'http_host':args.host, 'stateless':args.stateless})
    _run_http() if CFG['transport'] == 'http' else _run_stdio()

if __name__ == '__main__':
    main()