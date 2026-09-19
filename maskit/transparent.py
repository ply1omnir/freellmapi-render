"""
mitmproxy 本地显式代理 - 只拦目标站点聊天接口，脱敏请求 + 还原响应。
被 panel.py 以子进程方式启动：
    mitmdump -s transparent.py --listen-host 127.0.0.1 -p 5802 --mode ...

配置读同目录 config.json（panel.py 维护）。
日志输出结构化行供面板解析：SHIELD\\tTYPE\\t...
"""
# 数据面具 Maskit — 本地 LLM 敏感信息脱敏代理
# Copyright (C) 2026 TMW
#
# 本程序是自由软件：你可以依据自由软件基金会发布的 GNU Affero 通用公共许可证
# （版本 3）条款重新分发和/或修改它。
# 本程序基于「希望有用」的目的分发，但不附带任何担保；亦无对适销性或特定用途
# 适用性的默示担保。详见 GNU Affero 通用公共许可证。
# 你应已随本程序收到一份 GNU AGPL 副本；若无，见 <https://www.gnu.org/licenses/>。
import codecs
import contextlib
import datetime
import ipaddress
import json
import logging
import os
import re
import time
import secrets
import uuid
from pathlib import Path
from mitmproxy import http
from urllib.parse import urlparse
from shield_defaults import (
    DEFAULT_DOMAINS,
    DEFAULT_PATHS,
    DEFAULT_SECRET_PREFIXES,
    DEFAULT_TTL,
    DEFAULT_UPSTREAMS,
    DEFAULT_BUILTIN_RULES,
    KNOWN_PUBLIC_DNS,
    parse_egress_proxy,
    extract_usage as _extract_usage,
)
from event_store import enqueue_event
from event_store import enqueue_audit_event
from credential_labels import CREDENTIAL_LABELS
import audit_signals as _audit
import base64
import hashlib
from typing import NamedTuple

# 内置正则规则（敏感词字面在 config.json，正则规则固定，避免 UI 误改）
ID_BOUND_L = r"(?<![A-Za-z0-9])"
ID_BOUND_R = r"(?![A-Za-z0-9])"
# IP 专用右边界：额外挡掉「后面还跟着 .数字」的情况。
# 原来只用 ID_BOUND_R，`编号 192.168.1.1.1` 会把前 4 段当 IP 打码、剩个孤零零的
# `.1` 在后面，用户看到的是被截半的编号。5 段以上不是 IPv4，直接放过。
IP_BOUND_R = r"(?![A-Za-z0-9]|\.\d)"

# 公网 IPv4 专用边界：强防误伤定宽断言
# 左边界：挡住字母数字、字母数字连字符/下划线（lib-1.2.3.4/app_1.2.3.4）、包名域名点号前缀与多段版本截断
IP_PUBLIC_BOUND_L = r"(?<![A-Za-z0-9][-_])(?<![A-Za-z0-9]\.)(?<![A-Za-z0-9])"
# 右边界：挡住字母数字、点号文件后缀（.jar/.tar.gz/.js）与连字符标签/构建号后缀（-beta/-SNAPSHOT/-5）
IP_PUBLIC_BOUND_R = r"(?![A-Za-z0-9]|\.[A-Za-z0-9]|[-_][A-Za-z0-9])"
RULES = [
    # PEM 私钥整块替换（最高危凭据，形态固定零误报）——审计规则专项 P0。
    # 多行匹配：-----BEGIN ... PRIVATE KEY----- 到 -----END ... PRIVATE KEY-----
    # 整块替换成单个占位符，不逐行扫描。
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]{20,}?-----END[^-]*PRIVATE KEY-----"), "PRIVATE_KEY", 0),
    (re.compile(r"(?<![A-Za-z0-9_-])(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}(?![A-Za-z0-9_-])"), "API_KEY", 0),
    # GitHub fine-grained PAT: github_pat_<22>_<59+>（2022 GA，现为 GitHub 推荐默认形态）。
    # 老的 ghp_ 规则匹配不到它（前缀不同），实测 github_pat_... 整串漏检。
    # 前缀极其独特，无误报风险。
    (re.compile(r"(?<![A-Za-z0-9_-])github_pat_[A-Za-z0-9_]{50,}(?![A-Za-z0-9_-])"), "API_KEY", 0),
    # 云厂商 AK 家族（审计规则专项 P1）：形态固定零误报。
    # Google API Key: AIza[0-9A-Za-z_-]{35,38}（实际长度 39-42，AIza + 35~38）
    (re.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35,38}(?![A-Za-z0-9_-])"), "API_KEY", 0),
    # 阿里云 AK: LTAI[A-Za-z0-9]{12,20}
    (re.compile(r"(?<![A-Za-z0-9_-])LTAI[A-Za-z0-9]{12,20}(?![A-Za-z0-9_-])"), "ACCESS_KEY", 0),
    # 腾讯云 SecretId: AKID + 32 位。上界原为 20，比真实长度短一截，
    # 后缀 (?![A-Za-z0-9_-]) 又要求整串吃完 → 真实 36 位 SecretId 恒不命中
    # （实测 36 位示例串完全漏检）。放宽到 32。
    (re.compile(r"(?<![A-Za-z0-9_-])AKID[A-Za-z0-9]{13,32}(?![A-Za-z0-9_-])"), "ACCESS_KEY", 0),
    # Slack Token: xox[baprs]-[0-9A-Za-z-]{10,}
    (re.compile(r"(?<![A-Za-z0-9_-])xox[baprs]-[0-9A-Za-z-]{10,}(?![A-Za-z0-9-])"), "API_KEY", 0),
    # Stripe Key: [sr]k_(live|test)_[0-9A-Za-z]{20,}
    (re.compile(r"(?<![A-Za-z0-9_-])[sr]k_(?:live|test)_[0-9A-Za-z]{20,}(?![A-Za-z0-9])"), "API_KEY", 0),
    # 飞书 app: cli_[a-z0-9]{16,} / 钉钉: ding[a-z0-9]{6,}
    (re.compile(r"(?<![A-Za-z0-9_-])cli_[a-z0-9]{16,}(?![a-z0-9])"), "API_KEY", 0),
    (re.compile(r"(?<![A-Za-z0-9_-])ding[a-z0-9]{6,}(?![a-z0-9])"), "API_KEY", 0),
    (re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"), "ACCESS_KEY", 0),
    # AWS SecretAccessKey：40 位 base64（含 / 和 +）。裸串不敢匹配——任何 40 位
    # base64 摘要都会中招（误报优先级高于覆盖率），所以只认「键名 = 值」形态。
    # 这半边才是能直接花钱的：AKIA 泄漏本身无害，配上 SK 才能签请求。
    # 现有 SECRET 规则救不了它：值字符类不含 / 且有 (?!/) 前瞻，实测整串漏检。
    (re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"), "ACCESS_KEY", 1),
    (re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"), "JWT", 0),
    (re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{20,})"), "TOKEN", 1),
    # SECRET 值排除 {}：占位符 {{LABEL_hex}} 不再被当值二次替换（曾把
    # api_key=sk-xxx → 前缀规则先换占位符 → SECRET 再把占位符包一层，
    # 响应还原时嵌套占位符残留）。
    # 值：ASCII 无空白、不以 / 开头（/token=/api_key= 说明文案误报源）、
    # 不含换行/引号/中文/括号、且不含 .（曾把代码方法名/成员访问
    # ModelUtils.toStringSafe、getSecret 当凭据脱敏——真实凭据无点）。
    # 值还须含数字或特殊符号（(?=.*[0-9!@#$%^&*])）：纯字母标识符
    # （CamelCase 方法名/变量名）不再误报，真实凭据几乎必含数字/符号。
    # 键名与值两侧的引号都要吃掉：真实泄漏面大量来自用户直接粘 .env / JSON / YAML
    # 配置块（{"api_key": "sk..."} / password="hunter2000"），只认裸 key=value 会整块漏。
    # 引号只作可选边界、不进捕获组（组 2 仍是纯值），还原时不会把引号一起吞掉。
    # 关键词必须同时覆盖中英文、分隔符必须同时覆盖半角与全角：本产品面向中文用户，
    # 提示词里写的是「安装令牌：xxx」「数据库密码：xxx」，而原规则只认英文关键词 +
    # 半角 [:=]，实测 5/7 的中文凭据场景整条原文上行（SHIELD-CRED-CJK-001）。
    # 中文关键词不需要英文那种 (?<![A-Za-z0-9_.]) 边界：汉字本就不在该字符类里。
    # 值的字符类不含汉字，所以「密码：请联系管理员」这类正常中文句子不会误报。
    (re.compile(
        r"(?i)(?:(?<![A-Za-z0-9_.])(?:password|passwd|pwd|secret|token|api[_-]?key"
        r"|access[_-]?key|private[_-]?key)(?![A-Za-z0-9_.])"
        r"|(?:密码|口令|令牌|密钥|秘钥|密匙|凭据|凭证|私钥|授权码|访问密钥|接口密钥))"
        r"[\"'“”「」]?\s*[:=：＝]\s*[\"'“”「」]?(?!/)"
        r"(?=[A-Za-z0-9!@#$%^&*_~+=-]*[0-9!@#$%^&*])"
        r"([A-Za-z0-9!@#$%^&*_~+=-]{6,64})(?![A-Za-z0-9!@#$%^&*_~+=-])"
    ), "SECRET", 1),
    # 连接串密码：scheme://user:pass@host 形态，只脱密码组（第2组），
    # 保留 scheme/user/host——模型仍能理解这是连接串（审计规则专项 P0）。
    # EMAIL 规则的注释里曾提到 postgres://user:secret123@db.internal 被误当邮箱，
    # 修了误报但没补漏检。
    # scheme 段必须封顶 {0,63}：`[a-z0-9+.-]*` 无上限时，在「大量词起始位置 +
    # 长 [a-z0-9+.-] 连续段」的文本上是 O(N²)——实测 8/16/32KB 为 82/335/1345ms
    # （每次翻倍 ≈4x），同步阻塞 event loop。封顶后 32KB 降到 7.4ms、倍率 2.0。
    # 真实 scheme 最长不到 40 字符，封顶不损失任何匹配。
    # 注意：`_smoke_data/_rxstress.py` 对这个模式是**假阴性**（它的对抗串
    # `"x://" + "a"*n + ":"` 只有 2 个 \b 起点，形不成乘积），语料已补齐。
    (re.compile(r"(?i)\b[a-z][a-z0-9+.-]{0,63}://[^\s:@/]+:([^\s@/]{4,})@"), "CONNSTR", 1),
    # 手机号：连续 11 位，或 138-1234-5678 / 138 1234 5678（分隔符仅 - 或空白）；
    # +86 前缀整体脱敏（曾只脱 138... 部分，国家码原文残留）。
    # 加号可省（8613812345678 是国内表单/短信网关最常见写法）：国家码后紧跟
    # 1[3-9] 且两侧有非字母数字边界，与时间戳（17xxxxxxxxxxx）、订单号形态不冲突，
    # 实测 commit 8613812345678abcdef 因右边界含字母仍不命中。
    # 手机号：连续 11 位，或 138-1234-5678 / 138 1234 5678（分隔符仅 - 或空白）；
    # +86 / 0086 / (86) 前缀整体脱敏。
    # 分组分隔符必须前后一致（反向引用），或整体无分隔。
    (re.compile(ID_BOUND_L + r"(?:(?:\+?86|0086|[\(（]\+?86[\)）])[\s-]?)?1[3-9]\d(?:([-\s])\d{4}\1\d{4}|\d{8})" + ID_BOUND_R), "PHONE", 0),
    # 邮箱：本地部分首字符须为字母/数字/下划线/中文（排除 +- 等符号，防止 Git diff 的 +
    # 符号或列表 - 符号被当成用户名一部分吞噬）。
    # 本地部分前不能是 :（连接串 user:pass@host 形态防误伤），亦不能紧跟在其他词法字符后。
    # 下划线必须留在首字符类里：它同时在负向断言集合内，两边都排除会让 `_svc@corp.com`
    # 整段不匹配（首字符不是 `_`、从 `s` 起又被断言挡住）→ 明文漏检（2026-09 复审）。
    (re.compile(r"(?<!:)(?<![A-Za-z0-9._\u4e00-\u9fff])[a-zA-Z0-9_\u4e00-\u9fff][\u4e00-\u9fffA-Za-z0-9._%+-]{0,63}@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z\u4e00-\u9fff]{2,}(?![A-Za-z0-9._%+-])"), "EMAIL", 0),
    # 座机：3位区号(010/02x)或4位区号(03xx-09xx) + 分隔符/括号 + 7-8位本地号 + 可选分机号。
    (re.compile(
        ID_BOUND_L +
        r"(?:(?:\+?86|0086|[\(（]\+?86[\)）])[\s-]?)?"
        r"(?:"
          r"[\(（]0(?:10|2\d|[3-9]\d{2})[\)）][\s-]?[2-9]\d{6,7}"
          r"|"
          r"0(?:10|2\d|[3-9]\d{2})[-\s][2-9]\d{6,7}"
        r")"
        r"(?:[-\s]?(?:转|分机|ext|x|#)[-\s]?\d{1,5})?" +
        ID_BOUND_R,
        re.IGNORECASE
    ), "LANDLINE", 0),
    # 车牌：汉字省份 + 字母 + 5 位普通 / 6 位新能源
    # 车牌：省份简称 + 发牌机关字母 + 5-6 位车身。
    # **车身必须含至少一个数字**（0.1.15 修，实测误报 233 次）：左边界
    # `(?<![A-Za-z0-9])` 只挡 ASCII、挡不住汉字，而「新」是新疆简称——
    # 于是 `更新README.md` 里的「新README」被整段当成车牌脱掉，
    # 用户看到自己的文档名变成 {{PLATE_xxx}}。真车牌车身几乎必有数字，
    # README / ABCDEF 这类全字母串没有，一个前瞻就能分开，不必枚举词表。
    # 代价：全字母的个性化车牌会漏——那种在国内不发牌，可接受。
    (re.compile(r"(?<![A-Za-z0-9])[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领][A-Z](?=[A-Z0-9]{0,5}\d)[A-Z0-9]{5,6}(?![A-Z0-9])"), "PLATE", 0),
    # 港澳通行证：仅 H 开头 8 位（曾含 M——M+8 位数字与日期/变量名
    # M20260805 无法区分，误伤面大；规则默认关，用户真需要可在敏感词页开启）
    (re.compile(ID_BOUND_L + r"H\d{8}" + ID_BOUND_R), "HKID", 0),
    # 身份证（0.1.18 合并为单一开关 IDCARD，覆盖 15 位旧证 + 18 位二代证；
    # 两条正则同 label，校验按匹配长度分发：
    #   15 位：省份 + 真实公历出生日期（_idcard15_ok）；
    #   18 位：省份 + 出生日期 + ISO 7064 MOD 11-2 校验位（_idcard18_ok）。
    # 历史占位符 {{IDCARD18_xxx}} 的还原不受影响——还原靠 token 查复用表，
    # 与签发时的 label 无关；新签发的 18 位证统一用 {{IDCARD_xxx}}。
    # 旧配置的 IDCARD18 键由 panel.load_config 一次性迁移合并（meta.idcard_merged）。
    (re.compile(ID_BOUND_L + r"(?:1[1-5]|2[1-3]|3[1-7]|4[1-6]|5[0-4]|6[1-5]|71|8[12])\d{13}" + ID_BOUND_R), "IDCARD", 0),
    (re.compile(ID_BOUND_L + r"(?:1[1-5]|2[1-3]|3[1-7]|4[1-6]|5[0-4]|6[1-5]|71|8[12])\d{15}[\dXx]" + ID_BOUND_R), "IDCARD", 0),
    # 内网 IP 拆两个 label：IP_PRIVATE（192.168/链路本地，默认开——不会当版本号）、
    # IP_INTERNAL（10.x/172.16-31，默认关——10.x 是最常见版本号格式，
    # 曾把 version 10.2.3.4 脱敏成占位符，用户问版本号时模型看不到数字）
    # IP 规则同 label 合并为一条（交替分支），减少全文扫描次数（性能优化：
    # 每条规则独立 finditer 全文，18 条规则 = 18 次 O(长度) 扫描；同 label
    # 合并语义完全一致（同一占位符 label），仅省扫描次数）
    (re.compile(ID_BOUND_L + r"(?:192\.168\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})" + IP_BOUND_R), "IP_PRIVATE", 0),
    # 100.64.0.0/10（CGNAT 段）：Tailscale / ZeroTier / 运营商大内网全用这一段。
    # 归 IP_PRIVATE 而不是 IP_INTERNAL（默认关）——这段地址只可能是内网基础设施，
    # 不像 10.x 那样会跟版本号撞形。实测缺口：ssh tanmw@100.118.224.56 原文直出。
    # 第二段限定 64-127，避免把 100.0.x / 100.200.x 这类普通数字串卷进来。
    (re.compile(ID_BOUND_L + r"100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}" + IP_BOUND_R), "IP_PRIVATE", 0),
    (re.compile(ID_BOUND_L + r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})" + IP_BOUND_R), "IP_INTERNAL", 0),
    # IPv6 私网地址（fe80:: 链路本地 / fc00::/7 ULA，默认关——IP 系规则全部
    # 默认关，防含冒号 hex 串误伤）：宽正则抓候选（≥2 个冒号的 hex 串），
    # 语义校验 _ipv6_private_ok 保证只脱私网段。公网 IPv6（2001:... 等）不做
    # ——误伤面与 IP_PUBLIC 同源（版本号/UUID 形态），有真实需求再评估。
    # UUID 含 4 个连字符无冒号，不会进候选。
    # 前视断言不得排除 `:`：`gateway:fd00::5`、`IPV6:fe80::1` 这类「键:值」写法里
    # 地址紧跟冒号，排除 `:` 会让整段一个起点都匹配不上（IPv4 的 ID_BOUND_L 只排除
    # 字母数字，两类规则的边界本就不该不一致）。hex 与 `.` 仍排除，防止从长 hex 串
    # 中间起匹配；更长的地址会被贪婪吃成一条候选，再由语义校验否掉。
    (re.compile(r"(?<![0-9A-Fa-f.])[0-9A-Fa-f:]{2,45}(?![0-9A-Fa-f:])"), "IPV6_PRIVATE", 0),
    # 公网 IPv4：放 network 规则末尾（IP_INTERNAL 之后），作为泛化规则兜底。
    # 严格限定各段 0-255，语义校验由 _ip_public_ok 剔除私网保留段、组播与知名公共 DNS。
    (re.compile(IP_PUBLIC_BOUND_L + r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d?|[1-9])(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})" + IP_PUBLIC_BOUND_R), "IP_PUBLIC", 0),
    # 银行卡：13-19 位数字，必须以 3-6 开头（真卡 BIN：3=Amex/JCB，4=Visa，
    # 5=MasterCard，6=银联/Discover），且过 Luhn。位数范围按 ISO/IEC 7812——
    # 旧版只匹配 16 位，把国内主流的 19 位银联借记卡（62 开头）整类漏掉。
    #
    # **分隔符不能用 `[\s-]?` 逐位可选**（0.1.15 修，实测误报）：那样写等于允许
    # 每一位数字前插一个空格，匹配会跨过空格把两个不相干的数字接起来。
    # 生产实测把文件列表里的「大小 + 年份」当成了卡号：
    #   313524224 2023  → 拼成 3135242242023（13 位）→ Luhn 恰好通过
    #   4983554048 2025 → 拼成 49835540482025（14 位）→ Luhn 恰好通过
    # Luhn 只能挡掉 90%（随机数 1/10 概率通过），拦不住这类。而脱敏侧误报
    # = 破坏用户请求：模型收到的是 {{CARD_xxx}} 而不是那个文件大小。
    #
    # 现在分两支，都不允许「一位一空格」：
    #   1) 无分隔：连续 13-19 位数字；
    #   2) 分组：分隔符用反向引用强制**前后一致**（同 MAC 的修法），每组 1-6 位，
    #      首组 3-6 位。真卡分组是 4-4-4-4 / 4-6-5 / 4-4-4-4-3 / 4-4-4-1，
    #      没有哪种会出现 9 位一组——误报样本正是栽在这。
    # 位数由 _card_ok 显式校验（组数可变，正则不再隐式保证 13-19 位）。
    (re.compile(ID_BOUND_L + r"(?:[3-6]\d{12,18}|[3-6]\d{2,5}(?:([ -])\d{1,6}){1,4})" + ID_BOUND_R), "CARD", 0),
    # IBAN：2 字母 + 2 数字 + ≥11 位字母数字，需过 mod-97（欧洲银行账号，中文场景少见，校验严格防误伤）
    (re.compile(ID_BOUND_L + r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}" + ID_BOUND_R), "IBAN", 0),
    # 统一社会信用代码（审计规则专项 P2）：18 位，[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10}
    # 排除 I/O/S/V/Z 避免与普通字母数字串混淆。默认关——形态与普通字母数字串相近，
    # 政企场景用户需要时在敏感词页开启。
    (re.compile(ID_BOUND_L + r"[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10}" + ID_BOUND_R), "USCC", 0),
    # MAC 地址：xx:xx:xx:xx:xx:xx 或 xx-xx-xx-xx-xx-xx（审计 P1：
    # 分隔符用反向引用强制一致 + 去掉空格——曾用 [: -] 字符类，空格会让匹配
    # 从正文 'AC' 开始跨空格接上 MAC 片段，真 MAC 被切碎还吃掉周围文本）
    (re.compile(r"(?<![0-9A-Fa-f:-])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])"), "MAC", 0),
]

# 特征预检（性能优化，审计 P1 尾延迟）：每条规则配一个廉价必含特征
# （memchr 级子串查找，比 finditer 快一个数量级）。文本不含特征直接跳过
# 整条规则扫描——典型长对话（代码+中文）可跳过 JWT/TOKEN/API_KEY/IP 等
# 5-6 条规则，18 条全文扫描降到 ~12 条。特征必须保守（宁可漏检不误跳）：
# 只选规则"必须出现"的稳定片段；无可靠特征的规则（PLATE 汉字前缀、
# IDCARD/CARD 纯数字）不加，保留原扫描。
_RULE_MARKERS = {
    "PRIVATE_KEY": ("PRIVATE KEY",),  # PEM 私钥固定标记
    "CONNSTR": ("://",),      # 连接串必含 ://
    "API_KEY": ("gh", "AIza", "xox", "sk_", "rk_", "cli_", "ding"),  # GitHub/Google/Slack/Stripe/飞书/钉钉前缀
    # AWS/阿里云/腾讯云前缀。"aws"/"AWS" 是给 aws_secret_access_key= 那条规则用的：
    # 它整条是小写键名，不含 AK/LTAI/AKID 任何一个，不加就会被预检直接跳过。
    "ACCESS_KEY": ("AK", "LTAI", "AKID", "aws", "AWS"),
    "JWT": ("eyJ",),             # JWT 头固定
    # (?i)\bBearer\s+ 值。marker 是大小写敏感子串，三种常见大小写都要列：
    # 只列 Bearer/bearer 时全大写 "BEARER abc..." 连正则都跑不到（实测漏检）。
    "TOKEN": ("Bearer", "bearer", "BEARER"),
    # 规则要求 \s*[:=：＝]\s*。全角冒号/等号必须一并列出：预检命不中就整条规则跳过，
    # 中文用户写的「令牌：xxx」会连正则都跑不到（与 CGNAT 那次同一个坑）。
    "SECRET": ("=", ":", "：", "＝"),
    "PHONE": ("1",),             # 手机号 1[3-9] 开头
    "EMAIL": ("@",),             # 邮箱必含 @
    "LANDLINE": ("0",),          # 座机区号 0 开头
    # 加 "100."：CGNAT 段（Tailscale/ZeroTier）规则并进 IP_PRIVATE 后，
    # 预检特征也必须跟着加，否则整条规则被跳过、新规则等于没写（实测踩过）。
    "IP_PRIVATE": ("192.", "169.", "100."),
    "IP_INTERNAL": ("10.", "172."),
    # IPv6 私网首组必是 fe80-febf（fe8/fe9/fea/feb）或 fc00-fdff（fc/fd），
    # 用前缀做特征比 ":" 保守得多——':' 在任何 URL/JSON 里都命中，启用该规则
    # 后等于每条消息全量跑宽正则 + 海量 ipaddress 异常（31KB 文本实测 ~3400 次）。
    # 只列小写：该规则按大小写不敏感比对（见 _RULE_MARKERS_CI）。此前只列全小写与
    # 全大写，`Fe80::1` / `fE80::1` 这种混合大小写在预检处就被整条跳过且不留痕迹。
    "IPV6_PRIVATE": ("fe8", "fe9", "fea", "feb", "fc", "fd"),
}


# 预检必须大小写不敏感的规则（marker 是小写形态，比对前把文本降一次大小写）。
# 只对已启用该规则的文本生效（_rule_enabled 在调用点先短路），开销可忽略。
_RULE_MARKERS_CI = frozenset({"IPV6_PRIVATE"})

def _rule_may_hit(text, label):
    """特征预检：文本不含规则必含特征时跳过该规则扫描（性能）。"""
    markers = _RULE_MARKERS.get(label)
    if not markers:
        return True
    if label in _RULE_MARKERS_CI:
        # marker 只列了小写形态，比对前统一降一次大小写。不这么做的话，
        # `Fe80::1` / `fE80::1` 这类混合大小写在预检处就被判「不命中」，
        # 整条规则被静默跳过且不留痕（CGNAT 的 marker 漏加踩过同一个坑）。
        text = text.lower()
    return any(m in text for m in markers)


# 运行期配置（load 时从 config.json 读入）
TARGET_DOMAINS = list(DEFAULT_DOMAINS)
API_PATHS = list(DEFAULT_PATHS)
CUSTOM_WORDS = {}
# 自定义标签组禁用（组名仍保留在 config，只是 mask 时跳过）
SENSITIVE_DISABLED = set()
# 词级禁用：{label: set(words)}
SENSITIVE_WORD_DISABLED = {}
# 整词匹配开关：set(words) —— 开启后该词两侧加边界（不为字母数字/汉字），
# 避免「机要」打中「机要害」。默认对 2-3 字词不开（靠词长区分），用户显式开启（审计规则专项 P2）。
SENSITIVE_WORD_WHOLE = set()
# 内置规则开关（按 label；False 则 mask/scan 跳过该标签全部正则）
BUILTIN_RULES = dict(DEFAULT_BUILTIN_RULES)
SESSION_TTL = DEFAULT_TTL
DEBUG = False  # 调试：写完整 body（含真实原文）到 debug-日期.log
DIAGNOSTIC_UNMATCHED = False  # 诊断：只记录未命中请求元数据，不记录 body
DOMAINS_DISABLED = set()  # 被禁用的站点（不拦截，流量直连）
SECRET_PREFIXES = list(DEFAULT_SECRET_PREFIXES)
CAPTURE_MODE = "reverse"  # reverse | explicit | local
UPSTREAMS = list(DEFAULT_UPSTREAMS)  # 反向代理路由表
# 出口代理（Shield → 上游方向）：mitmproxy ServerSpec `(scheme, (host, port))`，None=不启用。
# 逐 flow 生效（`flow.server_conn.via`），所以同一个进程里可以「anyrouter 直连 +
# 官方 API 走代理」并存。实测走的是 CONNECT 隧道（即便目标是明文 http），
# 因此上游代理必须支持 CONNECT；socks5 不支持（mitmproxy 的 via 只认 http/https）。
EGRESS_PROXY = None
# 凭据类标签：唯一定义源在 credential_labels.py（panel / event_store 共用同一份，
# 前端 TS 侧由测试守同步）。以前这里各写一份，event_store 那份少两个标签 →
# 读路径会把 CONNSTR 密码与 PEM 私钥当普通 PII 返回。
# 凭据原文精确清洗的长度下限：内置规则最短的凭据捕获是 CONNSTR 的 {4,}，
# 自定义前缀规则要求前缀后 ≥8 位，SECRET 是 6-64 —— 真实凭据不会短于 4。
_MIN_SCRUB_LEN = 4
# 过滤开关：True=脱敏还原（默认），False=透明转发（不脱敏，流量原样到上游）。
# 代理仍运行、端口仍监听、路由仍生效，仅跳过脱敏/还原逻辑。客户端 base_url 不用改。
FILTER_ENABLED = True
# fail-closed（默认开）：脱敏管线异常时阻断请求返回 503，绝不放行含原文的 body 上行。
# 关闭 = 异常时记录 ERR 后仍继续转发（可能泄露原文，仅排查问题时临时关闭）。
FAIL_CLOSED = True
# 响应侧扫描（默认开）：还原后检查模型回复中不在本会话映射里的 PII（幻觉/训练数据泄漏），只记录事件不阻断。
RESPONSE_SCAN = True
# SSE 实时转发（默认开）：逐事件还原后立即下发，流末再做完整审计/扫描收尾。
STREAM_RESPONSE = True
# 字节级精确替换（默认开）：命中敏感词时只替换被脱敏的那个字符串字面量，
# 不再整棵 `json.dumps` 重序列化，从而保住客户端 body 的原始排版 —— 上游按前缀
# 做的 Prompt Cache 只会从真正的敏感值处失效，而不是从 body 开头附近就失效
# （实测一条带空格 + `\u` 转义的请求：敏感值在 byte 74，旧实现的差异位在 byte 9）。
# 结果必须通过 `json.loads(结果) == 脱敏后的树` 等价校验才会被采用，不过就自动
# 退回重序列化，所以它**不改变发往上游的内容**，只改变排版。
# 排查用的一键退路：环境变量 MASKIT_BYTE_SPLICE=0 即回到整棵重序列化的旧行为。
BYTE_SPLICE = os.environ.get("MASKIT_BYTE_SPLICE", "1") not in ("0", "false", "False")
# 流式接管黑名单：确认某上游接管后断连时，把 host 加进来保持整包路径。
# 仅在配置里**没有** stream_exclude_hosts 键时作为回落默认（老配置兼容）；
# 键存在即以配置为准，空列表 = 用户显式清空 = 不排除任何 host。
#
# 默认已清空。此前的 opencode.ai 条目是误判：断连并非上游限制，而是
# _sse_stream_factory 在「本次无完整 SSE 事件可发」时返回 b""，被 mitmproxy 的
# ResponseData 分支按 chunked 语法写成 b"0\r\n\r\n"（终止块），客户端据此判定
# 响应结束并关连接。改为返回空列表后，opencode.ai 实测 112 chunk / 11 个到达
# 时刻 / 1.09s 出字窗口，与直连同量级。是否复现只取决于上游的 TCP 分片是否
# 切开事件边界，与 host 无关，故不再预置任何 host。
_DEFAULT_STREAM_EXCLUDE_HOSTS = set()
STREAM_EXCLUDE_HOSTS = set(_DEFAULT_STREAM_EXCLUDE_HOSTS)
# 2.0 审计配置（默认开启被动检测，零影响脱敏还原）
AUDIT_ENABLED = True
AUDIT_PASSIVE = True
AUDIT_ACTIVE_PROBES = False
AUDIT_SEVERITY_FLOOR = "MEDIUM"
# 审计信号默认开关。这是信号清单的唯一来源：_read_settings 按本表的键遍历
# config.json，新增信号只改这里。曾在 _read_settings 里另写一份硬编码键列表，
# 加 S8/S9 时忘了同步 —— 结果第一次热重载就把 AUDIT_SIGNALS 换成 7 键字典，
# 两个信号在生产里静默失效而单测全绿（SHIELD-RELOAD-SIGNALS-001）。
DEFAULT_AUDIT_SIGNALS = {
    "error_leak": True,
    "identity_swap": True,
    "tool_call_rewrite": True,
    "sse_anomaly": True,
    "response_poison": True,
    "cross_request_pollution": True,
    "dangerous_action": True,  # S9 模型下发破坏性命令（只告警，不阻断）
}
AUDIT_SIGNALS = dict(DEFAULT_AUDIT_SIGNALS)
# 审计严重信号触发时自动停用该 upstream（默认关，用户自选）。
# 检测到 CRITICAL（如跨请求污染=relay 存了并复述了前序数据）时阻断后续请求（审计规则专项 P2）。
AUDIT_FAIL_CLOSED = False
# AI 实体识别开关（默认关闭，需用户显式开启，避免概率模型干扰确定性规则）
NER_ENABLED = False
# 主动探针注入的 canary nonce 注册表（跨请求污染检测用）
# 结构：{nonce: ts}，按 ts 清理过期 nonce，避免无界增长
_AUDIT_CANARY_REGISTRY = {}
_AUDIT_REGISTRY_TTL = 3600  # nonce 保留 1 小时
_AUDIT_REGISTRY_MAX = 500   # 上限 500 nonce，超则清最早
_ROOT = Path(__file__).parent.resolve()
# 流式响应留存上限：只为审计/响应侧扫描保留还原后文本，超过即不再累积（防大响应吃内存）
_SSE_KEEP_MAX = 256 * 1024
# 流式半事件/半行缓冲上限：buf 只暂存「没凑齐分隔符的半个事件」，正常上游事件远小于此值。
# 恶意/异常上游若持续推送不含分隔符的数据（非标准实现），buf 会无限增长吃光内存——
# 超限时把整个缓冲按最终事件强制还原下发并清空，宁多一次事件边界也不让内存失控。
_SSE_BUF_MAX = 4 * 1024 * 1024
# 响应侧扫描体长上限：几 MB 文本 × 全量规则正则会霸占事件循环，扫描是防御性功能，
# 超长只扫前段（代价：超长响应的尾部命中可能漏，属刻意取舍）。
_SCAN_BODY_MAX = 512 * 1024
# 扩展链路单会话的 stream_id 缓冲条目上限（审计 M2）。stream_id 由页面提供、
# 完全可控，而 `ext_frames` 是会话内的一个普通 dict：启用站点上的任意脚本都能在
# 会话 TTL 内不断换 id 把引擎内存撑大。超限按插入序淘汰最老的一条 ——
# 淘汰只丢「半帧缓冲」，被淘汰的流下次调用从空缓冲重来，最差结果是该条流上
# 跨帧切开的占位符拼不回来，而那是没有这套缓冲时的本来行为。
_EXT_FRAMES_MAX = 64
# 流式逐回调调试日志开关（SHIELD_STREAM_DEBUG=1）。默认关：SSE 每秒几十次回调，
# 常开会把日志刷爆并拖慢转发。断流排障时临时打开。
_STREAM_DEBUG = (os.environ.get("SHIELD_STREAM_DEBUG") or "").strip() not in ("", "0", "false", "False")
# in-flight 会话的硬回收上限：ts 静默超过此值即认为连接已死（上游断连／被中间
# 设备静默丢弃，流回调收不到空块、error 钩子也未必上报），强制回收避免会话与
# 脱敏原文映射永久驻留。取 15 分钟：远大于正常长生成的块间隔（有数据就 _touch
# 刷新 ts），又能兜住死连接。
_INFLIGHT_MAX_IDLE = 900
# 请求体脱敏上限（32MB）。脱敏要对全文跑十几条正则并重新序列化 JSON，全部在
# mitmproxy 的 asyncio event loop 上**同步**执行——超大 body 会连带冻结所有其他
# 连接（含进行中的 SSE 流）。正常 LLM 请求（含多模态 base64 图片）远达不到这个
# 量级，到这里基本是异常客户端或误发文件，按 fail-closed 拒绝比拖垮整个代理好。
_MAX_REQUEST_BODY = 32 * 1024 * 1024
# 数据目录：打包后从 LLM_SHIELD_DATA_DIR 环境变量读（panel.py 启动子进程时设置）；开发时回退到脚本目录
_DATA_ROOT = Path(os.environ.get("LLM_SHIELD_DATA_DIR") or str(_ROOT)).resolve()
_skip_seen = {}
_skip_seen_last_purge = 0.0

# ========== 引擎 ==========
sessions: dict = {}


def _debug(tag, sid, text):
    """调试日志：含真实敏感数据，仅排障用。"""
    if not DEBUG:
        return
    try:
        fn = _DATA_ROOT / f"debug-{time.strftime('%Y%m%d')}.log"
        head = f"\n==== {time.strftime('%Y-%m-%d %H:%M:%S')} {tag} sid={sid} ====\n"
        with open(fn, "a", encoding="utf-8") as f:
            f.write(head)
            f.write(text if isinstance(text, str) else str(text))
            f.write("\n")
    except Exception:
        pass


def _touch(sid):
    s = sessions.get(sid)
    if s:
        s["ts"] = time.time()


def _new_session(sid, source=None):
    sessions[sid] = {
        "fwd": {},
        "rev": {},
        "labels": {},
        # pending: {通道 -> 半截占位符}。流式响应里每个 delta 字段一个通道，
        # 避免上一个字段没闭合的占位符被拼进下一个字段（会把内容错位/吞字段）。
        "pending": {},
        # flush_tmpl: {通道 -> 最后一个该通道事件的 JSON}，收尾补发残留文本时做模板
        "flush_tmpl": {},
        "restored": 0,
        "restored_tokens": set(),
        "restored_origs": set(),
        "unresolved": 0,
        # 靠宽松兜底修回来的占位符数（模型把 {{}} 剥掉/写残，_LOOSE_PLACEHOLDER_RX
        # 捞回来的那些）。是成功路径，但值得看见：它说明模型在改写输出格式，
        # 是「哪天彻底还原不回来」的前兆。在这里显式初始化——原来只在
        # _loose_sub 里 s.get("degraded", 0)+1 隐式创建，没在会话结构里登记过，
        # 读的人不知道有这个字段（而且它压根没被发进事件，见 _restore_emit）。
        "degraded": 0,
        "last_hits": set(),
        "new_orig": set(),
        # 本次请求签发的占位符里，有没有「沿用复用表旧 token」的。
        # 只用于 MASK 事件的诊断字段（suffix_reused），不参与任何决策：
        # 全为 True 说明占位符后缀长期稳定，上游前缀缓存仍有机会命中；
        # 全为 False 的长会话说明每轮都在重签，缓存必然逐轮失效。
        "suffix_reused": False,
        # inflight: 请求已发出、响应未到。长生成（>SESSION_TTL）期间
        # 不能让 _sweep 按 ts 误删会话，否则整包路径响应到达时查不到 rev，
        # 占位符全部泄漏且不报错（P1-2）。
        "inflight": False,
        # 耗时统计：req_ts=请求到达（wall clock，事件展示用）；req_t0=perf_counter
        # 基准点（耗时计算用，精度 μs——time.time() 秒级，毫秒级请求会算成 0）；
        # mask_ms=脱敏管线；resp_ts=响应到达；first_byte_ms=流式首字节
        "req_ts": time.time(),
        "req_t0": time.perf_counter(),
        "mask_ms": 0.0,
        "resp_ts": None,
        "first_byte_ms": None,
        "ext_frames": {},
        "ts": time.time(),
        "source": source or {},
    }


def _drop(sid):
    sessions.pop(sid, None)


def _luhn_ok(num: str) -> bool:
    """Luhn 校验（银行卡）。"""
    digits = [int(c) for c in num if c.isdigit()]
    if len(digits) < 12:
        return False
    s, dbl = 0, False
    for d in reversed(digits):
        if dbl:
            d = d * 2 - 9 if d > 4 else d * 2
        s += d
        dbl = not dbl
    return s % 10 == 0


def _card_ok(orig: str) -> bool:
    """银行卡最终判据：去掉分隔符后必须是 13-19 位纯数字，且过 Luhn。

    位数校验以前是靠正则形状隐式保证的（`[3-6]\\d{3}(?:[\\s-]?\\d){9,15}`
    恰好 13-19 位）。0.1.15 把正则改成「无分隔 | 一致分隔符分组」两支之后，
    分组那支的组数可变、位数不再由正则锁死，必须在这里显式验——
    漏了它就会把 `554048 2025` 这种 10 位串当卡号。
    """
    digits = re.sub(r"[ -]", "", str(orig or ""))
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    return _luhn_ok(digits)


_IDCARD_W = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_IDCARD_CODE = "10X98765432"

_PROVINCES = {
    "11", "12", "13", "14", "15",
    "21", "22", "23",
    "31", "32", "33", "34", "35", "36", "37",
    "41", "42", "43", "44", "45", "46",
    "50", "51", "52", "53", "54",
    "61", "62", "63", "64", "65",
    "71", "81", "82",
}


def _idcard18_ok(num: str) -> bool:
    """GB 11643-1999 身份证 18 位多重严格校验：
    1. 省份行政区划代码合法（11-82）；
    2. 出生年月日真实性检验（1880 ~ 当前年份，含闰年 2 月 29 日与各月真实天数）；
    3. ISO 7064:1983.MOD 11-2 加权求模校验码匹配。
    """
    if not isinstance(num, str) or len(num) != 18 or not num[:17].isdigit():
        return False
    if num[:2] not in _PROVINCES:
        return False
    try:
        y, m, d = int(num[6:10]), int(num[10:12]), int(num[12:14])
        birth = datetime.date(y, m, d)
        now_year = datetime.datetime.now().year
        if not (1880 <= birth.year <= now_year):
            return False
    except ValueError:
        return False
    total = sum(int(d) * w for d, w in zip(num[:17], _IDCARD_W))
    return num[17].upper() == _IDCARD_CODE[total % 11]


def _idcard15_ok(num: str) -> bool:
    """GB 11643-1989 身份证 15 位综合有效性校验：
    1. 省份行政区划代码合法（11-82）；
    2. 出生年月日（YYMMDD -> 19YY-MM-DD）必须构成 1900~1999 年间真实的公历日期（含平闰年与月天数）。
    过滤掉时间戳、雪花 ID、订单号等任意非日期 15 位数字串。
    """
    if not isinstance(num, str) or len(num) != 15 or not num.isdigit():
        return False
    if num[:2] not in _PROVINCES:
        return False
    yy = int(num[6:8])
    mm = int(num[8:10])
    dd = int(num[10:12])
    try:
        birth = datetime.date(1900 + yy, mm, dd)
        if not (1900 <= birth.year <= 1999):
            return False
    except ValueError:
        return False
    return True


def _idcard_ok(num: str) -> bool:
    """身份证统一校验（0.1.18 合并开关后）：按匹配长度分发。
    15 位 → _idcard15_ok（省份 + 19YY 真实日期）；
    18 位 → _idcard18_ok（省份 + 真实日期 + ISO 7064 校验位）。
    正则已分别锁定位数，这里只做长度分发，避免误用。
    """
    if not isinstance(num, str):
        return False
    if len(num) == 18:
        return _idcard18_ok(num)
    if len(num) == 15:
        return _idcard15_ok(num)
    return False


def _phone_ok(num_str: str) -> bool:
    """国内手机号校验：
    1. 提取核心 11 位纯数字；
    2. 严格 1[3-9] 开头；
    3. 排除全同重复数字（如 11111111111）。

    只挡 set==1 的全同号：set<=2 会误杀 13131313131（131 联通，set={1,3}=2）
    等真实在用号段。全同号 11111111111 的特征是 set==1，正则 1[3-9] 已挡住
    其第二位，这里只是双保险，不该误伤任何 2 种数字以上的合法号。
    """
    digits = re.sub(r"\D", "", str(num_str or ""))
    if digits.startswith("86") and len(digits) == 13:
        digits = digits[2:]
    elif digits.startswith("0086") and len(digits) == 15:
        digits = digits[4:]
    if len(digits) != 11:
        return False
    if not (digits[0] == "1" and digits[1] in "3456789"):
        return False
    if len(set(digits)) == 1:
        return False
    return True


def _landline_ok(num_str: str) -> bool:
    """国内固定电话号码校验：
    1. 必须以 0 开头（支持 3 位区号 010/02x 及 4 位区号 03xx~09xx）；
    2. 本地号码 7~8 位，首位 2~9（排除 0/1 开头非法本地号——国内普通座机
       无 1 开头号段，9 为付费/特殊号保守放行）；
    3. 带可选分机号。
    """
    digits = re.sub(r"\D", "", str(num_str or ""))
    if digits.startswith("86"):
        digits = digits[2:]
    elif digits.startswith("0086"):
        digits = digits[4:]
    if not (10 <= len(digits) <= 17):
        return False
    if not digits.startswith("0"):
        return False
    # 本地号首位：010/02x 是 3 位区号，本地号从第 4 位起；03xx-09xx 是 4 位区号，从第 5 位起。
    # 国内本地号首位 2-9（1 开头无此号段，0 开头非法）。正则已用 [2-9] 挡住首位 0/1，
    # 这里做双保险，防正则后续放宽后漏校验。
    if len(digits) >= 4 and digits[1] in "12":
        # 3 位区号 01x/02x
        local_first = digits[3]
    elif len(digits) >= 5 and digits[1] in "3456789":
        # 4 位区号 0xxx
        local_first = digits[4]
    else:
        return False
    if local_first not in "23456789":
        return False
    return True


def _email_ok(email_str: str) -> bool:
    """邮箱地址校验：
    1. 包含合法用户名与域名；
    2. 排除连续双点及冒号前缀连接串；
    3. 顶级域名至少 2 位。
    """
    s = str(email_str or "").strip()
    if "@" not in s or s.startswith("@") or s.endswith("@"):
        return False
    parts = s.split("@")
    if len(parts) != 2:
        return False
    local, domain = parts[0], parts[1]
    if len(local) < 1 or len(domain) < 3 or "." not in domain:
        return False
    if local.startswith(".") or local.endswith(".") or ".." in local or ".." in domain:
        return False
    tld = domain.split(".")[-1]
    if len(tld) < 2:
        return False
    return True


def _iban_ok(iban: str) -> bool:
    """IBAN mod-97 校验：字母 A=10..Z=35，前 4 位移尾后整体 mod 97 余 1。"""
    s = iban.strip()
    if len(s) < 15 or not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", s):
        return False
    reordered = s[4:] + s[:4]
    digits = "".join(str(ord(c) - 55) if c.isalpha() else c for c in reordered)
    try:
        return int(digits) % 97 == 1
    except Exception:
        return False


def _jwt_ok(token: str) -> bool:
    """JWT 真伪校验：第一段（eyJ...）base64url 解码后必须是含 alg 的 JSON header。
    只按三段形态匹配会把长 base64 串误判为 JWT（曾无校验直接脱敏）。"""
    try:
        head = token.split(".")[0]
        pad = "=" * (-len(head) % 4)
        decoded = base64.urlsafe_b64decode(head + pad).decode("utf-8", errors="replace")
        return '"alg"' in decoded
    except Exception:
        return False


# ---- CONNSTR 误报豁免的形态常量 ----
# 全部提到模块级：mask() 是热路径，一次请求可能命中上万条连接串，
# 函数内每次调用重建 set / 编译正则纯属浪费（审计 2026-09 复审）。
# 判据一律「锚定整体形态」，**绝不**用字符类判「密码里含模板符号」——
# 曾用 `re.search(r"[{<\[\$%]", orig)`，结果 `Xk9$mQ2p`、`p%40ssw0rd` 这类
# 真实口令被判成模板而豁免，明文直接上行（详见 _connstr_ok 注释）。
_CONNSTR_TPL_RXS = (
    re.compile(r"^\$?\{[A-Za-z_][A-Za-z0-9_]*\}$"),   # {password} / ${PORT}
    re.compile(r"^<[A-Za-z_][A-Za-z0-9_]*>$"),        # <password>
    re.compile(r"^\[[A-Za-z_][A-Za-z0-9_]*\]$"),      # [password]
    re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$"),        # $PORT
    re.compile(r"^%[A-Za-z_][A-Za-z0-9_]*%$"),        # %PWD%
)
# 通配占位：**** / ... / xxxx
_CONNSTR_WILDCARD_RX = re.compile(r"^[xX*.]+$")
# 文档保留 / 占位主机（RFC 2606 的 example.* 与常见教程主机名）
_CONNSTR_DUMMY_HOSTS = frozenset({
    "host", "hostname", "myhost", "server", "myserver",
    "example.com", "example.org", "example.net",
    "test.com", "sample.com", "your-host", "yourhost", "yourdomain.com",
})
_CONNSTR_DUMMY_HOST_SUFFIXES = (".example", ".invalid")
# 经典教学占位凭据对
_CONNSTR_PLACEHOLDER_USERS = frozenset({"user", "username", "your_username", "yourusername", "usr", "guest"})
_CONNSTR_PLACEHOLDER_PASSWORDS = frozenset({
    "pass", "password", "passwd", "your_password", "yourpassword", "changeme", "change_me", "guest",
})
# 一次请求里最多记录多少条「被豁免的连接串原文」供下游规则避让。
# 上界只为防病态输入：集合是去重的，文档模板反复出现只会留 1 条；
# 超过上界后不再记录，最坏结果是下游规则照常脱敏（安全方向）。
_CONNSTR_EXEMPT_MAX = 512

# `@` 之后的 authority（host[:port]）。IPv6 字面量必须整体吃进 `[...]`：
# 按 `split(":", 1)` 拆 `[::1]:5432` 会得到 host=`[`、port=`::1`，
# 非数字端口判定随即把它当模板豁免 —— 真实口令明文上行（复审实测漏检）。
_CONNSTR_AUTH_RX = re.compile(r"^(?:\[[^\]\s]*\](?::[^\s/?#\"'`)>},;]*)?|[^\s/?#\"'`)>\]},;]*)")


def _connstr_authority(text: str, pos: int):
    """取 pos 处的 authority，返回 (host, port)；port 无端口时为空串。"""
    tail = text[pos:pos + 256] if text else ""
    m = _CONNSTR_AUTH_RX.match(tail)
    auth = m.group(0) if m else ""
    if auth.startswith("["):
        host, _, rest = auth.partition("]")
        return host, (rest[1:] if rest.startswith(":") else "")
    host, sep, port = auth.partition(":")
    return host, (port if sep else "")


def _connstr_ok(orig: str, m=None, text: str = "") -> bool:
    """连接串密码真伪校验：只豁免「一眼是文档/代码模板」的形态，其余照常脱敏。

    判据分四档，任一档成立才豁免（**fail-closed：拿不准就脱敏**）：

      1. 端口非数字（`:port` / `:<port>` / `:{port}` / `:$PORT`）**且**用户名或密码是
         占位形态 —— RFC 3986 规定端口必须是纯数字，非数字端口是模板；但「端口是模板」
         推不出「密码是假的」，单凭端口豁免会把 `https://svc:secret123@db.internal:port/x`
         的真实口令原样放行。
         ⚠️ 佐证项**不含占位主机**：主机像模板同样是「端口是模板」的同类信号，拿它当
         佐证等于循环论证，会把 `postgres://admin:S3cret99@host:port/db` 整体豁免
         （实测 12 个占位主机名全部漏检，2026-09 复审）。主机只在第 3 档与「密码是占位词」
         **同时**成立时才算证据。
         另外要求端口里一个数字都没有：`:5432x` 这种带数字的照常脱敏。
      2. 密码整体是锚定模板形态：`{password}` / `<password>` / `[password]` /
         `$PORT` / `%PWD%` / `****` / `xxxx`。
      3. 主机是文档保留域名或占位词（host / example.com / test.com …）**且**密码也是
         占位词 —— 只查主机不查密码，会把 `admin:S3cret99@host:5432` 这类真实口令放行。
      4. 用户名与密码是经典教学组合（user:pass / username:password）。

    历史教训（2026-09 复审，两处必须记住的坑）：
      · 用字符类 `[{<\\[\\$%]` 判「密码含模板符号」会把真实口令判成模板而豁免，
        `mysql://root:p%40ssw0rd@…` 直接全明文上行。
      · 豁免本身还会**放走下游规则**：CONNSTR 让路后排在后面的 EMAIL 规则会把
        「口令尾@host」整段当邮箱吃掉，输出 `postgres://app:Xk9${{EMAIL_x}}:5432/prod`
        —— 看着有占位符、实际口令前半截明文上行，最危险的一类。
        由 mask() / 扫描路径里的 `exempt_conn` 区间列表负责避让，两处必须成对修改
        （判据见 `_overlaps_exempt_conn`：只跳过**与豁免区间重叠**的 EMAIL 命中）。
    """
    if not isinstance(orig, str) or not orig:
        return False
    if _CONNSTR_WILDCARD_RX.match(orig):
        return False
    if any(rx.match(orig) for rx in _CONNSTR_TPL_RXS):
        return False
    if m is None:
        return True

    try:
        # 从 `scheme://user:pass@` 里回推 username
        prefix = m.group(0)
        user_part = ""
        if "://" in prefix:
            _scheme, rest = prefix.split("://", 1)
            idx = rest.rfind(":" + orig + "@")
            user_part = rest[:idx] if idx != -1 else rest.split(":", 1)[0]

        host, port = _connstr_authority(text, m.end())
        host_lower = host.lower().strip("[]")
        user_lower = user_part.lower()
        pass_lower = orig.lower()
        host_dummy = (host_lower in _CONNSTR_DUMMY_HOSTS
                      or host_lower.endswith(_CONNSTR_DUMMY_HOST_SUFFIXES))
        user_dummy = user_lower in _CONNSTR_PLACEHOLDER_USERS
        pass_dummy = pass_lower in _CONNSTR_PLACEHOLDER_PASSWORDS

        # 1. 非数字端口。注意：端口是模板 ≠ 密码是假的，我们决定的是「要不要脱密码」，
        #    所以还要一个弱信号佐证 —— 但佐证只能是**用户名或密码**是占位词。
        #    曾把 host_dummy 也算进来，等于「端口像模板 + 主机像模板 ⇒ 密码是假的」：
        #    主机像模板和端口像模板是同一类信号，循环论证，实测
        #    `postgres://admin:S3cret99@{host|example.com|db.example|…}:port/db` 12/12 全漏，
        #    真实口令原样上行（2026-09 复审）。主机要到第 3 档、与占位密码同时成立才算数。
        #    端口里不含任何数字才认（`:5432x` 这种带数字的照常脱敏）。
        if port and not any(ch.isdigit() for ch in port):
            if user_dummy or pass_dummy:
                return False

        # 2. 占位主机：必须「主机 + 密码」同时像占位才豁免。
        #    只查主机不查密码，会把 `admin:S3cret99@host:5432` 这类真实口令放行。
        if host_dummy and pass_dummy:
            return False

        # 3. 经典教学凭据对（user:pass / username:password）
        if user_dummy and pass_dummy:
            return False
    except Exception:
        # 校验自身出错时保守脱敏（绝不把疑似凭据放明文出网）
        return True

    return True


def _overlaps_exempt_conn(start: int, end: int, spans) -> bool:
    """EMAIL 命中 [start, end) 是否与被豁免的连接串**重叠**。

    为什么判「重叠」而不是「紧接其后」（2026-09-13 修正）：
    连接串的 CONNSTR 命中止于 userinfo 结尾的 `@`（host/port 在 `m.end()` 之后由
    `_connstr_authority` 单独解析），所以真正需要避让的 EMAIL 命中是**起点落在豁免
    串内部**的那些——它们才是「口令尾@host」，脱掉一半会留半截口令明文。
    而「起点正好在豁免串之后」的 EMAIL 命中是**独立的真实邮箱**（例如
    `redis://default:{password}@zhang.san@example.com:6379` 里那个 `@example.com`
    主机名形式的邮箱），把它一起跳掉等于新增一条漏检：实测 guard 开着时该邮箱
    明文上行，关掉才被正常脱敏。

    ⚠️ 判据必须是重叠、不能只看「前一个字符是不是 `@`」：后者既挡不住口令尾
    （口令在 `@` 之前，前一个是 `:`），又会误伤紧跟其后的真实邮箱。
    把本函数整体改成 `return False` 时 660 个用例仍全过 —— 说明它此前**没有任何
    用例保护**，改这里务必同步补用例。

    `spans` 由 finditer 顺序追加，天然按 start 递增且互不重叠，故一旦
    `s_start >= end` 即可提前结束。
    """
    if not spans:
        return False
    for s_start, s_end in spans:
        if s_start >= end:
            break
        if start < s_end and end > s_start:
            return True
    return False


_prefix_rx_cache = None
_prefix_rx_key = None


def _ip_public_ok(orig: str) -> bool:
    """公网 IPv4 校验：排除已知公共 DNS、版本号形态、私网、环回、组播及保留段。

    两层版本号启发式（规则默认关，宁漏勿误伤）：
    1. 四段全个位数（1.2.3.4 / 2.0.1.0）：开发文本里压倒性偏向版本号与教学
       示例；真实公网主机的全个位数地址只有知名 anycast DNS，已全部枚举进白名单。
    2. 构建号形态（首段个位 + 第三段为 0 + 末段三位数，如 Java 1.8.0.202 /
       2.4.0.101）：Java/构建号版本的标准形状。第三段必须为 0——不加这条的
       话 5.189.128.100 这类真实公网主机（AWS/Level3 的 3.x/5.x/8.x 段常见）
       会被放行（复审实测）。
    漏检面（fail-open，已知取舍）：全个位数非白名单段（8.8.8.1）、构建号形态
    真实主机（5.189.0.100）不脱；由默认关闭 + 元数据标注兜底。
    """
    if not isinstance(orig, str) or orig in KNOWN_PUBLIC_DNS:
        return False
    try:
        parts = orig.split(".")
        # 四段全个位数：视为版本号/教学示例放行（白名单已在上面先判）
        if all(len(part) == 1 for part in parts):
            return False
        # 构建号形态：首段个位 + 第三段为 0 + 末段三位数（100-255）
        if len(parts[0]) == 1 and parts[2] == "0" and len(parts[-1]) == 3:
            return False
        addr = ipaddress.IPv4Address(orig)
        return addr.is_global and not addr.is_multicast
    except ValueError:
        return False


# USCC（统一社会信用代码）字符集与 MOD31 权重：GB 32100-2015。
# 权重因子 31^i mod 31 不会循环出 0（31 是素数），官方即用 1..31 直接乘。
_USCC_CHARS = "0123456789ABCDEFGHJKLMNPQRTUWXY"
_USCC_WEIGHTS = (1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28)


def _ipv6_private_ok(orig: str) -> bool:
    """IPv6 私网校验：仅 fe80::/10（链路本地）与 fc00::/7（ULA）算命中。

    宽正则抓来的候选绝大多数不是 IPv6（MAC、时间、端口号串），先靠
    ipaddress 解析剔除；解析成功的再看是否私网段。注意不能用
    IPv6Address.is_private——它把 2001:db8::/32（文档段）、::1（环回）等
    全算 private，公网讨论文本里的这些地址会被误脱（实测 2001:db8::1
    被 is_private 放行进打码）。只认 ULA 与链路本地两段，其余一律放行。
    带 zone id（fe80::1%eth0）的解析会失败——剥掉 % 后缀再试一次，
    链路本地地址带 zone 是 Linux 网络配置的常态写法。
    """
    if not isinstance(orig, str) or orig.count(":") < 2:
        return False
    candidate = orig.split("%", 1)[0]
    try:
        addr = ipaddress.IPv6Address(candidate)
    except ValueError:
        return False
    return addr.is_link_local or (addr in ipaddress.IPv6Network("fc00::/7"))


def _uscc_ok(orig: str) -> bool:
    """USCC 校验位验证（GB 32100-2015 MOD31）。

    18 位 = 登记管理部门(1) + 机构类别(1) + 登记管理机关(6) + 主体标识(9) +
    校验位(1)。前 17 位加权求和 mod 31，映射到字符集取校验位比对。
    规则默认关；开启后校验位把随机字母数字串的误伤率压到 1/31 以下。
    """
    if not isinstance(orig, str) or len(orig) != 18:
        return False
    try:
        total = sum(_USCC_WEIGHTS[i] * _USCC_CHARS.index(orig[i]) for i in range(17))
        check = (31 - total % 31) % 31
        return _USCC_CHARS[check] == orig[17]
    except ValueError:
        return False


def _prefix_secret_regex():
    global _prefix_rx_cache, _prefix_rx_key
    key = tuple(SECRET_PREFIXES)
    if key == _prefix_rx_key and _prefix_rx_cache is not None:
        return _prefix_rx_cache
    # - / _ 视为等价（审计规则专项 P2）：用户配 sk- 不会漏掉 sk_live_，配 ghp_ 也兼容 ghp-。
    # 把前缀中的 - 和 _ 都展开成 [-_] 字符类。逐字符安全转义，防二次替换嵌套。
    prefixes = ["".join("[-_]" if ch in ("-", "_") else re.escape(ch) for ch in p) for p in SECRET_PREFIXES if p]
    if not prefixes:
        _prefix_rx_cache = None
        _prefix_rx_key = key
        return None
    # 凭据后缀阈值：前缀匹配后跟随至少 8 位无空格密文字符（1+7 位）。
    # 之前硬编码 19 位（1+18）导致自建平台、内部鉴权或测试环境的 8~16 位自定义短 Key 严重漏判。
    # 设为 8 位既能彻底避开 sk-demo/sk-test 等极短日常词误伤，又能全面覆盖自定义短凭据。
    _prefix_rx_cache = re.compile(r"(?<![A-Za-z0-9_-])(?:" + "|".join(prefixes) + r")[A-Za-z0-9][A-Za-z0-9_-]{7,}(?![A-Za-z0-9_-])")
    _prefix_rx_key = key
    return _prefix_rx_cache


# ========== 占位符 ==========
# 格式：{{LABEL_后缀6位}}，纯 ASCII。后缀自 0.1.13 起是纯辅音（见下方 _TOKEN_ALPHABET），
# 存量 hex6 后缀仍继续识别（见 _SUFFIX_PAT）。
# 旧格式 ⟦X·hex⟧ 用生僻 Unicode 且不带语义：主流 tokenizer 会切成多个罕见 token，
# 模型复述时容易变形（少一个括号就还原失败），且模型不知道占位符代表什么，回答质量下降。
# 新格式保留业务标签（PHONE / EMAIL / TERM…），模型能理解"这里原本是个电话号"。
_LABEL_SAFE_RX = re.compile(r"[^A-Z0-9]+")


def _safe_label(label):
    """标签 ASCII 化。内置规则标签本身是 ASCII；自定义中文标签统一归 TERM。"""
    up = _LABEL_SAFE_RX.sub("", str(label or "").upper())
    return up[:12] or "TERM"


def _rand_suffix():
    """占位符后缀：6 位纯辅音（字符集与理由见 _TOKEN_ALPHABET）。

    用 secrets.choice 而不是 random：这个后缀是会话内实体的唯一标识，
    可预测的后缀会让上游能够枚举、关联同一实体。
    """
    return "".join(secrets.choice(_TOKEN_ALPHABET) for _ in range(6))


def _new_token(label):
    """生成不与近期占位符冲突的新占位符。

    冲突判定同时看**完整 token** 与**6 位后缀**：后缀索引按后缀反查，若两个
    存活 token 共用一个后缀，标签被改写时就会把 A 的原文替换到 B 的位置上。
    后缀空间 19^6≈4700 万、表内至多 _RECENT_MAX=2000 条，多一次后缀检查
    换来「索引永远无歧义」，这个代价是值的。
    """
    lab = _safe_label(label)
    for _ in range(20):
        token = "{{%s_%s}}" % (lab, _rand_suffix())
        if token not in _RECENT_REV and _token_suffix(token) not in _RECENT_SUFFIX:
            return token
    # 兜底仍用 6 位：长度必须落在 _SUFFIX_PAT 认得的范围内。
    # 原来这里返回 secrets.token_hex(6)（12 个字符），而正则只认 6 个——
    # 一旦触发，该 token 永远匹配不到、还原永久失败，且失败得毫无声响。
    # 实际不可达：19^6≈4700 万，表里至多 _RECENT_MAX=2000 条，
    # 单次撞上约 4.3e-5，连撞 20 次约 1e-88。
    return "{{%s_%s}}" % (lab, _rand_suffix())


# 跨请求占位符复用表（仅内存，TTL = session_ttl，带条数上限）。
# 解决两个真实问题：
# 1) 多轮对话里同一实体每轮拿到不同占位符，模型会当成不同的人；
# 2) 上一轮响应里没还原干净的占位符留在客户端历史里，下一轮请求带上来时无从还原，
#    会话被污染且永远不会自愈。复用表让历史占位符仍能查到原文（见 _lookup / _seed_known）。
# 代价：原文在内存中的保留窗口从"单请求"延长到 session_ttl，且同一原文在 TTL 内
# 对上游呈现同一占位符（可被关联）。TTL 到期即失效，不落盘。
_RECENT_FWD = {}   # orig -> [token, label, ts]
_RECENT_REV = {}   # token -> [orig, label, ts]
_RECENT_MAX = 2000

# 自定义敏感词持久化映射表（仅内存常驻，不随 TTL/LRU 淘汰）：
# 解决长任务、Agent 工具调用时因超过复用表 TTL 或引擎重启导致无法还原的问题。
# 自定义敏感词来自用户明确配置的 CUSTOM_WORDS，其原文已在配置文件中受控持久化，
# 因此其内存映射在运行时永久常驻，且通过确定性派生算法保证跨重启后缀一致。
_CUSTOM_WORD_FWD = {}  # orig -> token
_CUSTOM_WORD_REV = {}  # token -> [orig, label, ts]


def _deterministic_suffix(orig, used_suffixes=None):
    """为自定义敏感词生成确定性的 6 位纯辅音后缀。

    使用 SHA-256 确定性派生，在词表内发生碰撞时递增计数器避让。
    保证相同的敏感词在多次重启、跨会话中始终获得稳定相同的占位符，
    最大化上游 Prompt Cache 命中率并保证长任务工具调用可靠还原。
    """
    counter = 0
    while True:
        seed = f"maskit_cw:{counter}:{orig}".encode("utf-8")
        h = hashlib.sha256(seed).digest()
        suffix = "".join(_TOKEN_ALPHABET[b % len(_TOKEN_ALPHABET)] for b in h[:6])
        if used_suffixes is None or suffix not in used_suffixes:
            return suffix
        counter += 1


def _is_custom_word_orig(orig):
    """该原文是否属于**当前启用**的自定义敏感词（决定是否永久豁免 TTL/LRU）。

    必须连启用状态一起判：词或整组被禁用后仍返回 True 的话，它的映射会绕过
    TTL 与 LRU 永久驻留，与「复用表到期即失效」的原文驻留窗口契约冲突
    （见 SECURITY.md）。label 优先取已签发的 REV 记录，退回配置里的 label。
    """
    tok = _CUSTOM_WORD_FWD.get(orig)
    if tok is not None:
        rec = _CUSTOM_WORD_REV.get(tok)
        return _custom_word_enabled(orig, (rec[1] if rec else None) or CUSTOM_WORDS.get(orig, ""))
    if orig in CUSTOM_WORDS:
        return _custom_word_enabled(orig, CUSTOM_WORDS.get(orig, ""))
    return False


def _is_custom_word_token(tok):
    return tok in _CUSTOM_WORD_REV
# 启动预热时最多回读的事件条数（见 _warmup_recent_from_db）。复用表本来就有
# _RECENT_MAX 封顶，读再多也留不住，这个上限只是防止重度使用下几万条事件
# 逐条 json.loads 把引擎启动拖慢。
_WARMUP_MAX_EVENTS = 5000

# 后缀索引：6 位后缀 -> 完整 token。**只是 _RECENT_REV 的指针，不存原文**，
# 所以它不会延长原文在内存里的存活窗口，也不需要独立的 TTL。
#
# 解决什么：模型会把占位符的标签改写掉——`{{IPPRIVATE_x}}` 写成
# `{{IP_PRIVATE_x}}`（自己补回下划线）或 `{{ipprivate_x}}`（整段小写）。
# 标签一变，按完整 token 查表必然落空，而 6 位后缀是随机指纹、模型改不动它，
# 于是「按后缀反查」就能把它们救回来。
#
# 三条硬约束（都来自实测，不是保守起见）：
# 1. **只收录纯辅音后缀**。给正则加 IGNORECASE 之后，`config_abc123` /
#    `sha_abcdef` 这类「小写标识符 + `_hex6`」会命中宽松形态（实测）。今天
#    只是白查一次表，可一旦后缀索引介入就会把整段替换成明文，直接改坏用户
#    代码。hex6 后缀是存量格式、且在代码里天然常见，所以一律不进索引，
#    继续只走完整 token 精确匹配。
# 2. **只在带花括号的调用点使用**（restore 的严格遍与转义遍）。流式响应里
#    裸 token 被 chunk 切开后，残片（实测 `ATE_zwndfk`）会被宽松正则命中；
#    后缀索引一旦介入就会把残片替换成明文，拼出一条错的命令。
# 3. **标签归一化后必须相等**（见 _suffix_real_token）。后缀只有 47M 分之一的
#    碰撞概率，但一旦碰撞就是静默替换错值（把 A 的内网 IP 填到 B 的位置）。
#    所以 `{{HOST_x}}` 这种整段换名**不认**，宁可让它走 unresolved 让用户看见。
#
# 维护：_suffix_index_add / _suffix_index_del 是唯一入口，必须与
# _RECENT_FWD / _RECENT_REV 的写入、淘汰**成对出现**（见 _prune_recent、
# _warmup_recent_from_db、_recall_token 三处）。
_RECENT_SUFFIX = {}
# 后缀撞车标记：同一个后缀被两个存活 token 占用时写进索引值。
# 撞车后**永不参与兜底匹配**——「保留先来的那个」会把 A 的原文答给 B，
# 属于静默替换错值；拒答的代价只是这个后缀不再兜底，退化成改动前的行为。
_SUFFIX_AMBIGUOUS = object()

# 复用表用独立 TTL，不跟着 SESSION_TTL（默认 600s）走。
#
# 起因（实测）：agent 类客户端一个任务动辄跑几十分钟，上下文里始终带着几十轮前
# 的占位符。SESSION_TTL 一到，_RECENT_REV 里的映射就被清掉，之后模型回复里的
# 占位符查不到原文 → 原样透传给客户端 → 用户看到裸露的 {{IPPRIVATE_c81792}}，
# agent 把它当成真值去执行，命令直接失败。表现出来就是「还原功能坏了」，
# 实际是映射过期。
#
# 为什么不干脆调大 SESSION_TTL：那个值同时管 sessions 的回收，长对话的 fwd/rev
# 可能几千条且无上限，调大它是拿内存换命中率。复用表本身有 _RECENT_MAX=2000 封顶，
# 单独放宽到 24h 的内存代价是有界的（2000 条 × 两个方向）。
#
# 这张表本身仍不落盘：里面是原文明文，主动写盘等于把凭据写进磁盘，与
# 「凭据永不落库」直接冲突。
#
# 但 0.1.12 起启动时会从**事件库**做一次只读预热（_warmup_recent_from_db）：
# 那些 original 是用户明确要求落的日志（约束 5），本来就在盘上，读它不产生
# 任何新的磁盘写入，凭据类在库里也只有 digest 没有原文。所以
# 「引擎重启后历史占位符不可还原」这句自 0.1.12 起不再成立——
# 48h 内的普通 PII 映射能恢复，更早的仍然丢。
RECENT_TTL = 24 * 3600


def _recent_ttl():
    """复用表 TTL：至少 24h，用户把 session_ttl 调得更大时跟随。"""
    return max(RECENT_TTL, SESSION_TTL)


def _prune_recent(now=None):
    """按 TTL + 条数上限清理复用表，防止无界增长。

    后缀索引必须跟着一起删：它是指向 _RECENT_REV 的指针，留着指向已淘汰
    token 的条目虽然不会答错（_lookup_by_suffix 还会回查 _RECENT_REV），
    但会让 _new_token 白白避开一个已经空出来的后缀。
    """
    now = now or time.time()
    ttl = _recent_ttl()
    stale = [
        k for k, v in list(_RECENT_FWD.items())
        if not _is_custom_word_orig(k) and now - v[2] > ttl
    ]
    for k in stale:
        tok = _RECENT_FWD.pop(k, [None])[0]
        _RECENT_REV.pop(tok, None)
        _suffix_index_del(tok)
    if len(_RECENT_FWD) > _RECENT_MAX:
        evictable = [
            (k, v) for k, v in _RECENT_FWD.items()
            if not _is_custom_word_orig(k)
        ]
        # 配额只按**可淘汰**条数算：自定义词的规模由词表封顶，不该挤占普通条目的额度。
        # 拿总长度算欠额，词表越大就越先清掉普通 PII 的复用条目——词表接近
        # _RECENT_MAX 时，刚签发的普通占位符会被当场淘汰（复用与后缀容错一起失效）。
        over = len(evictable) - _RECENT_MAX
        if over > 0:
            oldest = sorted(evictable, key=lambda kv: kv[1][2])
            for k, v in oldest[:over]:
                _RECENT_FWD.pop(k, None)
                _RECENT_REV.pop(v[0], None)
                _suffix_index_del(v[0])


def _warmup_recent_from_db():
    """引擎启动时从本地 SQLite 事件库预热恢复历史占位符映射。

    解决：引擎发版升级、重启或进程崩溃后，客户端长对话里携带的历史占位符
    因内存表清空而 100% 还原不了。

    与 AGENTS 约束 7 的关系：那条写的是「复用表不落盘是有意的」——指的是
    **不新增落盘**。这里读的是事件库里**本来就有**的 `items[].original`
    （约束 5：用户明确要求日志含脱敏明文），不产生任何新的磁盘写入，
    所以不与该取舍冲突。约束 7 里「引擎重启后历史占位符不可还原」那句
    自 0.1.12 起不再成立，已同步改文档。

    安全保证：
    - 凭据类（API_KEY/TOKEN/SECRET/JWT/ACCESS_KEY/CONNSTR/PRIVATE_KEY）在库里
      本来就只有 digest+preview、没有 original，双重过滤后绝不会被预热；
    - 只读，不写库；
    - **数据目录严格隔离**：设了 LLM_SHIELD_DATA_DIR 就只认该目录，
      库不存在就什么都不预热。0.1.12 曾在该目录无库时静默回落
      %APPDATA%\\Maskit，导致隔离测试实例把用户生产库的真实 PII
      （实测 420 条，含身份证/银行卡/手机号）载入内存——违反 AGENTS 约束 23。
    """
    try:
        import sqlite3
        # 数据目录只认一处，不做候选回落：回落等于隔离环境读生产库。
        env_dir = os.environ.get("LLM_SHIELD_DATA_DIR")
        if env_dir:
            db_path = os.path.join(env_dir, "shield-events.sqlite3")
        else:
            appdata = os.environ.get("APPDATA")
            db_path = (os.path.join(appdata, "Maskit", "shield-events.sqlite3")
                       if appdata else "shield-events.sqlite3")
        if not os.path.isfile(db_path):
            return

        now = time.time()
        cutoff = now - 48 * 3600  # 恢复最近 48 小时内的映射
        # LIMIT 兜底：重度使用下 48h 可能有几万条事件，逐条 json.loads 会把
        # 引擎启动拖慢。倒序取最近的 _WARMUP_MAX_EVENTS 条足够覆盖活跃会话，
        # 而复用表本来就有 _RECENT_MAX 上限，多读也留不住。
        # 注意：sqlite3 的 with 只管事务不关连接，句柄不释放会锁住数据目录
        # （Windows 下隔离测试实例 cleanup 直接 PermissionError）。
        conn = sqlite3.connect(db_path, timeout=5)
        try:
            rows = conn.execute(
                "SELECT payload FROM events WHERE ts >= ? ORDER BY id DESC LIMIT ?",
                (cutoff, _WARMUP_MAX_EVENTS),
            ).fetchall()
        finally:
            conn.close()

        # 先按「最新事件优先」收集（rows 为 id 倒序），同一原文只留最新 token：
        # 旧 token 直接不登记，天然不产生 REV/后缀索引孤儿。
        seen_orig = set()
        collected = []
        for (payload_str,) in rows:
            try:
                p = json.loads(payload_str)
                for it in p.get("items", []) or []:
                    tok = it.get("tok")
                    orig = it.get("original")
                    label = it.get("label") or ""
                    if not tok or not orig or not _PLACEHOLDER_RX.match(tok):
                        continue
                    # 过滤凭据类与占位符自身
                    if label in CREDENTIAL_LABELS or _PLACEHOLDER_RX.match(orig):
                        continue
                    if orig in seen_orig:
                        continue
                    seen_orig.add(orig)
                    collected.append((tok, orig, label))
            except Exception:
                pass
        # 再按时间正序（旧→新）写入：所有条目的 ts 都是同一个 now，_prune_recent
        # 超容量时的稳定排序按插入序删——正序插入保证先删**最旧**映射。
        # 曾按倒序直接写入：恢复 >2000 条时反而把最新的映射先删掉，重启后
        # 活跃会话最需要的占位符还原命中率倒挂（审计 P2）。
        for tok, orig, label in reversed(collected):
            _RECENT_FWD[orig] = [tok, label, now]
            _RECENT_REV[tok] = [orig, label, now]
            _suffix_index_add(tok)
        count = len(collected)
        if count > 0:
            _prune_recent(now)
            _log(f"[shield-warmup] 从本地事件库预热 {count} 条占位符映射"
                 f"（复用表现有 {len(_RECENT_REV)} 条）")
    except Exception as e:
        _log(f"[shield-warmup] 预热映射失败 (静默跳过): {e}")


def _recall_token(orig, label):
    """取该原文的占位符：TTL 内复用旧的，否则新建并登记。"""
    # 安全防套娃：如果 orig 自身就是占位符，严禁为其分配新 token！
    if isinstance(orig, str) and _PLACEHOLDER_RX.match(orig):
        # 尝试反查其真实明文
        rec = _RECENT_REV.get(orig) or _CUSTOM_WORD_REV.get(orig)
        if rec and not _PLACEHOLDER_RX.match(rec[0]):
            orig = rec[0]
            label = rec[1] or label
        else:
            # 查不到真实明文，直接原样返回自身，绝不套娃生成新占位符
            return orig

    # 自定义敏感词优先使用稳定永久映射
    perm_token = _CUSTOM_WORD_FWD.get(orig)
    if perm_token:
        _touch_recent(perm_token, orig)
        _suffix_index_add(perm_token)
        return perm_token

    now = time.time()
    hit = _RECENT_FWD.get(orig)
    if hit and (_is_custom_word_orig(orig) or now - hit[2] <= _recent_ttl()):
        hit[2] = now
        rev = _RECENT_REV.get(hit[0])
        if rev:
            rev[2] = now
        # 幂等补登记：复用表里可能因预热撞车而没进索引（见 _suffix_index_add）
        _suffix_index_add(hit[0])
        return hit[0]
    token = _new_token(label)
    # 旧映射已过期：注销旧 token 的 REV / 后缀索引再覆盖 FWD。
    # 不注销的话旧条目成孤儿——_prune_recent 只扫 FWD 的值发现待删 token，
    # REV / _RECENT_SUFFIX 里的旧条目两个清理路径都碰不到，长驻进程缓慢泄漏。
    prev = _RECENT_FWD.get(orig)
    if prev and prev[0] != token:
        _RECENT_REV.pop(prev[0], None)
        _suffix_index_del(prev[0])
    _RECENT_FWD[orig] = [token, label, now]
    _RECENT_REV[token] = [orig, label, now]
    _suffix_index_add(token)
    _prune_recent(now)
    return token


def _remember(fwd, labels, orig, label):
    """登记原文→占位符映射；返回 True 表示沿用了复用表里的旧 token。

    返回值只用于诊断（MASK 事件的 `suffix_reused`）：沿用旧 token 说明占位符
    后缀与前缀都没变，上游按前缀做的 Prompt Cache 仍有机会命中；本次全新签发
    则意味着缓存必然从这个位置起失效。
    """
    if orig not in fwd:
        perm_token = _CUSTOM_WORD_FWD.get(orig)
        if perm_token:
            fwd[orig] = perm_token
            labels[orig] = label
            _touch_recent(perm_token, orig)
            return True
        hit = _RECENT_FWD.get(orig)
        reused = bool(hit) and (_is_custom_word_orig(orig) or time.time() - hit[2] <= _recent_ttl())
        fwd[orig] = _recall_token(orig, label)
        labels[orig] = label
        return reused
    return False


# 按长度降序的敏感词表（长词优先匹配，保证同一位置长词先命中）。
# 唯一消费者是 _custom_combined_regex，而它只在合并正则缓存未命中时才会走到这里，
# 所以下面的排序不进 mask 热路径。
_CUSTOM_WORDS_SORTED = ()


def _sorted_custom_words():
    """CUSTOM_WORDS 按词长降序的元组（长词优先）。"""
    return tuple(sorted(CUSTOM_WORDS.items(), key=lambda kv: len(kv[0]), reverse=True))


def _refresh_custom_words_sorted():
    """显式重建排序词表（热重载与测试直改词表后调用，用于预热）。"""
    global _CUSTOM_WORDS_SORTED
    _CUSTOM_WORDS_SORTED = _sorted_custom_words()
    _sync_custom_word_mappings()


def _custom_words_sorted():
    """取排序词表；**内容**变了才重建。

    曾只比长度（`len(cache) != len(CUSTOM_WORDS)`）：等长换词——例如把
    {张三, 李四} 换成 {密, 王五}——长度不变就不重建，于是继续沿用旧词表，
    新词不生效、旧词继续命中；现象还随用例/请求顺序漂移（曾让单字边界用例随机失败）。

    生产路径 reload_config 会显式重建，但把正确性寄托在「每个调用方都记得刷新」上
    太脆——任何绕过 reload 直改 CUSTOM_WORDS 的路径（主要是测试）都会中招。
    这里改成比内容，谁改词表都自动正确，不再依赖调用方纪律。
    """
    global _CUSTOM_WORDS_SORTED
    cur = _sorted_custom_words()
    if cur != _CUSTOM_WORDS_SORTED:
        _CUSTOM_WORDS_SORTED = cur
        _sync_custom_word_mappings()
    return _CUSTOM_WORDS_SORTED


# 凭据的「结构前缀」——这部分不是秘密，是各家公开的格式标记（sk-proj- 就是
# OpenAI 项目密钥，ghp_ 就是 GitHub PAT）。原样显示零风险，却是排查时最有用的信息。
_CRED_PREFIX_RX = re.compile(
    r"^(?:sk-proj-|sk-ant-[a-z0-9]{2,10}-|sk-|gh[pousr]_|github_pat_|AIza|AKIA|ASIA"
    r"|AKID|LTAI|xox[baprs]-|[sr]k_(?:live|test)_|cli_|ding|eyJ)"
)
# 机器生成的高熵凭据：给「前缀 + 末 4 位」足够定位是哪一把，剩余熵仍在天文数字级。
# 人选的低熵口令（SECRET/CONNSTR）不在此列——一个 10 位口令露首尾就等于露了大半。
_HIGH_ENTROPY_LABELS = {"API_KEY", "ACCESS_KEY", "TOKEN", "JWT"}


def _cred_preview(orig, label):
    """凭据预览：可识别，不可用。

    产品红线是「日志被人拿走也拿不到你的 key」，但一律打成 **** 走到了另一个极端——
    用户看到告警却不知道是哪一把泄露了，没法去吊销，安全能力等于零。
    折中按凭据类型分档：

      PRIVATE_KEY  只给密钥类型（RSA/EC/OPENSSH）。私钥任何一段都不能露。
      高熵凭据      结构前缀 + 末 4 位。前缀是公开格式标记，末 4 位与各家控制台
                   列表里的显示方式一致（GitHub/Stripe/AWS 都这么做），够你对上号。
      低熵口令      一个字符都不给，只给长度。数据库密码常常只有 8-12 位，
                   露首尾就是露大半。靠 digest 做同一性比对。

    精确定位始终可以用 digest（sha256 前 16 位）：本地对你手上的 key 算一次
    sha256 一比就知道是不是它，而 digest 本身不可逆。
    """
    s = str(orig or "")
    n = len(s)
    if label == "PRIVATE_KEY":
        m = re.search(r"BEGIN (?:(RSA|EC|DSA|OPENSSH|PGP) )?PRIVATE KEY", s)
        kind = (m.group(1) if m and m.group(1) else "PEM") if m else "PEM"
        return f"<{kind} 私钥 {n} 字节>"
    if label in _HIGH_ENTROPY_LABELS and n >= 20:
        m = _CRED_PREFIX_RX.match(s)
        head = m.group(0) if m else s[:4]
        return f"{head}…{s[-4:]}"
    # 低熵口令 / 太短的凭据：不给任何字符
    return f"<{label} {n} 位>"


def _preview(orig, label):
    """生成脱敏预览：凭据类不泄露可用信息，其他类型保留少量上下文。"""
    if label in CREDENTIAL_LABELS:
        return _cred_preview(orig, label)
    n = len(orig)
    if n <= 2:
        return orig[0] + "*" if n else ""
    if n <= 5:
        return orig[0] + "*" * (n - 1)
    if n <= 12:
        return orig[:1] + "*" * (n - 2) + orig[-1:]
    return orig[:2] + "**" + orig[-2:]


def _cred_digest(orig):
    """凭据的不可逆摘要（sha256 前 16 位）：日志/导出里可做同一性对照，不落明文。"""
    try:
        return hashlib.sha256(str(orig).encode("utf-8")).hexdigest()[:16]
    except Exception:
        return ""


def _redact_credentials(text):
    """把文本里所有凭据形态的值抹成 [REDACTED]（日志 dialog/preview 落库前清洗）。

    还原后的响应文本可能复述了模型见到的 api_key/token 原文，直接进事件库等于
    凭据明文落盘。这里用内置凭据规则 + 用户前缀规则过一遍，命中即抹掉。
    """
    if not isinstance(text, str) or not text:
        return text
    try:
        for rx, label, _g in RULES:
            if label in CREDENTIAL_LABELS:
                text = rx.sub("[REDACTED]", text)
        pref = _prefix_secret_regex()
        if pref:
            text = pref.sub("[REDACTED]", text)
    except Exception:
        pass
    return text


def _redact_session_credentials(text, s):
    """把**本会话脱敏过的凭据原文**从文本里精确抹掉（与 `_redact_credentials` 互补）。

    `_redact_credentials` 只按「凭据形态」跑正则，防的是「用户自己贴的、本会话没
    脱敏过的凭据」。它防不住另一种：还原后的响应里模型**只复述了值本身**——
    CONNSTR 的规则要求完整 `scheme://user:pass@host`，PRIVATE_KEY 要求 PEM 头，
    裸值都不命中形态正则，于是明文跟着 resp_dialog / resp_preview 落进 SQLite。

    引擎本来就知道原文（`s["fwd"]` 的 key 就是原文），所以这里做精确串替换。

    长度下限 `_MIN_SCRUB_LEN`：内置规则里最短的凭据捕获是 CONNSTR 的 `{4,}`，自定义
    前缀规则要求前缀后至少 8 位，SECRET 是 6-64——即**任何真实凭据原文都不会短于 4**。
    更短的只可能是「用户把 1-3 字符短词放进凭据类分类」这种配置，无法安全定位，
    整段不下发（见下方取舍说明）。
    """
    if not isinstance(text, str) or not text:
        return text
    try:
        labels = s.get("labels") or {}
        unsafe_short = False
        # 收集所有已知凭据原文：
        # 1. 本会话请求阶段自身脱敏的凭据（s["fwd"]）
        # 2. 跨请求从 _RECENT_REV 还原出来的历史凭据（s["restored_tokens"]）
        candidate_origs = set()
        for orig in (s.get("fwd") or {}):
            if labels.get(orig, "") in CREDENTIAL_LABELS:
                candidate_origs.add(orig)
        for tok in (s.get("restored_tokens") or set()):
            rec = _RECENT_REV.get(tok)
            if rec and len(rec) >= 2:
                orig, label = rec[0], rec[1]
                if label in CREDENTIAL_LABELS and orig:
                    candidate_origs.add(orig)

        for orig in candidate_origs:
            if orig not in text:
                continue
            if len(orig) < _MIN_SCRUB_LEN:
                unsafe_short = True
                continue
            text = text.replace(orig, "[REDACTED]")
        if unsafe_short:
            # 1-3 字符的原文无法安全定位：全局替换会把整段文本打成筛子（每个 "id"
            # 都变 [REDACTED]）。内置规则里最短的凭据捕获是 CONNSTR 的 {4,}、自定义
            # 前缀要求前缀后 ≥8 位，所以走到这里只可能是「用户把 1-3 字符的短词放进
            # 了凭据类分类」这种配置。与 `_scrub_legacy_event` 同一取舍：拿不准就整段
            # 不下发——放行原文是最坏结果。
            return "[REDACTED]"
    except Exception:
        pass
    return text


def _label_for_orig(s, orig):
    return s.get("labels", {}).get(orig, "")


def _host_matches(host, domain):
    host = (host or "").lower().rstrip(".")
    domain = (domain or "").lower().rstrip(".")
    return bool(domain) and (host == domain or host.endswith("." + domain))


def _path_matches(path, prefix):
    path = (path or "").split("?", 1)[0]
    prefix = prefix or ""
    return bool(prefix) and (path == prefix or path.startswith(prefix.rstrip("/") + "/"))


def is_target(host, path):
    if not any(_path_matches(path, p) for p in API_PATHS):
        return False
    for d in TARGET_DOMAINS:
        if _host_matches(host, d) and not any(_host_matches(host, off) for off in DOMAINS_DISABLED):
            return True
    return False


# ========== 反向代理路由 ==========

def _parse_upstream_target(target):
    """'https://api.openai.com' -> ('api.openai.com', 443, 'https', '', '')
    'https://api.example.com/v1?api-version=2024-02-15' -> (host, 443, 'https', '/v1', 'api-version=2024-02-15')

    target 带路径时（如 /v1、/zen/go/v1），透传层（panel）会拼回路径前缀；
    这里同样返回 path_prefix 与 query_prefix，反向代理路由转发时拼回，
    保证 Azure OpenAI、Gemini 或带版本号的上游 query 参数不丢失。
    """
    parsed = urlparse(target)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    scheme = parsed.scheme or "https"
    path_prefix = parsed.path.rstrip("/")
    query_prefix = parsed.query or ""
    return host, port, scheme, path_prefix, query_prefix


def _merge_path_and_query(path_prefix, target_query, client_path):
    """合并上游 target 前缀/query 与客户端请求路径/query，保证 api-version 等参数绝不丢失。"""
    if "?" in (client_path or ""):
        client_pure, client_q = client_path.split("?", 1)
    else:
        client_pure, client_q = client_path or "", ""

    if path_prefix:
        merged_path = path_prefix + (client_pure if client_pure.startswith("/") else "/" + client_pure)
    else:
        merged_path = client_pure or "/"

    queries = [q for q in (target_query, client_q) if q]
    merged_q = "&".join(queries)
    return merged_path + ("?" + merged_q if merged_q else "")


def _listener_port(flow):
    """获取 mitmproxy 本地监听端口（用于多端口模式路由）。"""
    conn = getattr(flow, "client_conn", None)
    if not conn:
        return None
    # mitmproxy 12.x: client_conn.sockname 是本地监听地址（含端口）
    for attr in ("sockname", "address"):
        sock = getattr(conn, attr, None)
        if callable(sock):
            try:
                sock = sock()
            except Exception:
                sock = None
        if not sock:
            continue
        try:
            # Address 可能是 tuple/list (host, port) 或对象
            if isinstance(sock, (list, tuple)) and len(sock) >= 2:
                return int(sock[1])
            # mitmproxy.net.http.Address 或类似对象，尝试 .port 属性
            port = getattr(sock, "port", None)
            if port is not None:
                return int(port)
            text = str(sock)
            if ":" in text:
                return int(text.rsplit(":", 1)[1])
        except Exception:
            continue
    return None


def _match_upstream_by_port(port):
    """多端口模式：按入站端口匹配 upstream。"""
    if not port:
        return None
    for up in UPSTREAMS:
        if int(up.get("port") or 0) == port:
            return up
    return None


def _match_upstream(path):
    """单端口前缀模式：按请求路径前缀匹配反向代理 upstream。
    返回 (upstream_dict, stripped_path) 或 (None, path)。
    base_path=/openai, 请求 /openai/v1/chat/completions?api-version=1 -> 剩余 /v1/chat/completions?api-version=1
    """
    clean = (path or "").split("?", 1)[0]
    query = ("?" + (path or "").split("?", 1)[1]) if "?" in (path or "") else ""
    for up in UPSTREAMS:
        base = (up.get("base_path") or "").rstrip("/")
        if not base:
            continue
        if clean == base:
            return up, "/" + query
        if clean.startswith(base + "/"):
            return up, (clean[len(base):] or "/") + query
    return None, path


def _upstream_path_ok(upstream, stripped_path, final_path=None):
    """检查路径是否在该 upstream 的 paths 白名单。

    target 带路径前缀时（如 /v1），白名单命中最终路径（带前缀）或剥前缀后的
    路径任一即可——上游配置的 paths 是 API 真实路径（如 /v1/chat/completions）。
    """
    paths = upstream.get("paths") or API_PATHS
    candidates = [final_path, stripped_path] if final_path else [stripped_path]
    for cand in candidates:
        sp = (cand or "").split("?", 1)[0]
        if any(_path_matches(sp, p) for p in paths):
            return True
    return False


def apply_reverse_routing(flow):
    """反向代理模式路由。优先多端口（按入站端口），回退单端口前缀（按 base_path）。
    多端口模式：客户端 base_url=http://127.0.0.1:<port>，不剥前缀，直接转发。
    单端口模式：客户端 base_url=http://127.0.0.1:5802/<base_path>，剥前缀后转发。
    返回 (matched_upstream_or_None, final_path)。未匹配时不动 flow。
    """
    path = getattr(flow.request, "path", "") or ""
    # 1. 多端口模式：按入站端口匹配
    port = _listener_port(flow)
    up = _match_upstream_by_port(port)
    if up:
        host, up_port, scheme, path_prefix, query_prefix = _parse_upstream_target(up["target"])
        try:
            flow.request.host = host
            flow.request.port = up_port
            flow.request.scheme = scheme
            flow.request.headers["Host"] = host
        except Exception:
            pass
        final = _merge_path_and_query(path_prefix, query_prefix, path)
        try:
            flow.request.path = final
        except Exception:
            pass
        return up, final
    # 2. 单端口前缀模式回退：按 base_path 匹配并剥前缀
    up, stripped = _match_upstream(path)
    if not up:
        return None, path
    host, up_port, scheme, path_prefix, query_prefix = _parse_upstream_target(up["target"])
    try:
        flow.request.host = host
        flow.request.port = up_port
        flow.request.scheme = scheme
        flow.request.headers["Host"] = host
        flow.request.path = stripped
    except Exception:
        # 测试用 SimpleNamespace 可能没有可写属性，退回只改 path
        try:
            flow.request.path = stripped
        except Exception:
            pass
    final = _merge_path_and_query(path_prefix, query_prefix, stripped)
    try:
        flow.request.path = final
    except Exception:
        pass
    return up, final


# 注入请求头的占位符形态：**整个值**就是 <...>（可带 Bearer 前缀）。
# 只匹配「整体就是占位符」，不做子串匹配——真实 header 值（application/json、
# 真 key、URL）里不会整值长这样，所以不会误伤正常配置。
_EXTRA_HEADER_PLACEHOLDER_RX = re.compile(r"^\s*(?:Bearer\s+)?<[^<>]{1,64}>\s*$", re.IGNORECASE)

# 凭据类请求头：语义就是「承载身份凭据」，一律禁止通过 extra_headers 注入。
#
# 为什么单列一份名单：Maskit 的定位是**只配 URL 的透明转发网关**，凭据归客户端所有
# （Claude Code / Cursor 等都会自带）。在这个字段里填凭据没有任何正当场景，只会把
# 客户端自带的真 key 覆盖成配置里的值——填错就是必然 401，而用户从上游看到的只有
# 「无效的令牌」，根本联想不到是自己的配置造成的（实测 anyrouter 中转站报障即此因）。
#
# 与凭据无关的协议头不受影响，例如 anthropic-version、anthropic-beta
# （实测 claude-sonnet-4-5 必须带 anthropic-beta: context-1m-2025-08-07 才能用 1M 上下文）。
#
# 比对方式：头名转小写后精确匹配（HTTP 头名大小写不敏感），不做子串匹配，
# 所以 x-api-key-version 这类自造头不会被误伤。
_CREDENTIAL_HEADER_NAMES = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "api-key",
    "apikey",
    "x-goog-api-key",
    "x-auth-token",
    "x-access-token",
    "x-token",
    "x-session-token",
    "private-token",
    "x-gitlab-token",
    "x-github-token",
    "x-amz-security-token",
    "x-amz-credential",
    "x-client-secret",
    "client-secret",
})

# 同一 (客户端, 头名) 只告警一次，避免每个请求刷一行日志；config reload 时清空。
_EXTRA_HEADER_SKIP_WARNED = set()


def _apply_extra_headers(flow, upstream):
    """按 upstream 配置注入静态请求头（extra_headers）。

    场景：上游要求某个**与凭据无关**的协议头，但客户端根本不发
    （典型：anthropic-beta: context-1m-2025-08-07），在转发前注入。
    仅 reverse 模式（客户端流量必经本钩子）；值含敏感信息只进内存配置，不落日志。

    **三类值一律跳过注入**：

      1. 凭据头（authorization / x-api-key / cookie …，见 `_CREDENTIAL_HEADER_NAMES`）：
         凭据属于客户端，Maskit 只做 URL 转发。在这里填凭据只会覆盖客户端自带的真 key，
         换回一个必然 401——而上游报的只是「无效的令牌」，用户看不出是自己配置造成的。
      2. 占位符值（整个值就是 `<...>`，可带 Bearer 前缀，如 `<YOUR_API_KEY>`）：
         永远不可能是真实凭据，注入等于用一个假 key 顶掉真 key。
      3. 空值：空字符串不是凭据，注入等于把客户端的头清掉，比不注入更糟。

    三者都跳过之后，请求退回「客户端自带凭据」的正常路径：用户即使没填也不会挂，
    真要注入的协议头照常按真实值覆盖。
    """
    try:
        extra = (upstream or {}).get("extra_headers") or {}
        if not isinstance(extra, dict) or not extra:
            return
        up_name = str((upstream or {}).get("name") or "")
        for key, value in extra.items():
            k = str(key or "").strip()
            if not k:
                continue
            v = str(value)
            if k.lower() in _CREDENTIAL_HEADER_NAMES:
                if (up_name, k) not in _EXTRA_HEADER_SKIP_WARNED:
                    _EXTRA_HEADER_SKIP_WARNED.add((up_name, k))
                    _log(f"[mask] 客户端「{up_name}」的注入请求头 {k} 属于凭据头，已跳过注入"
                         f"（凭据请配在客户端里，Maskit 只做透明转发；"
                         f"此处填凭据会覆盖客户端自带的真凭据并导致上游 401）")
                continue
            if not v.strip() or _EXTRA_HEADER_PLACEHOLDER_RX.match(v):
                if (up_name, k) not in _EXTRA_HEADER_SKIP_WARNED:
                    _EXTRA_HEADER_SKIP_WARNED.add((up_name, k))
                    why = "值为空" if not v.strip() else f"仍是占位符 {v}"
                    _log(f"[mask] 客户端「{up_name}」的注入请求头 {k} {why}，已跳过注入"
                         f"（请在设置页填入真实值或删除该行；跳过不会影响客户端自带的凭据）")
                continue
            try:
                flow.request.headers[k] = v
            except Exception:
                pass
    except Exception:
        pass


def _apply_egress_proxy(flow, upstream):
    """按 upstream 配置决定本次转发是否经由出口代理（Shield → 上游方向）。

    机制：mitmproxy 的 `flow.server_conn.via` 是**按连接**的上游代理指定，
    `make_server_connection()` 建连时读取（本项目用 `connection_strategy=lazy`，
    连接在 request 钩子之后才建，时机正好）。因此同一个 mitmdump 进程里可以
    「境内中转直连 + 境外官方 API 走代理」并存，不必像环境变量方案那样一刀切。

    **必须在 request() 里所有 return 分支之前调用**：`/v1/models`、健康检查这类
    「路由命中但不脱敏、提前 return」的请求同样要走代理，漏掉就会直连境外上游，
    表现为「聊天能用但客户端初始化失败」这种极难归因的半残状态。

    实测注意：即便目标是明文 http，mitmproxy 也通过 CONNECT 隧道走代理，
    所以上游代理必须支持 CONNECT（Clash/v2ray 的 http 端口都支持）。
    仅 reverse 模式生效；explicit 模式另有 `--mode upstream:` 机制，不在此处理。
    """
    if not EGRESS_PROXY or not isinstance(upstream, dict) or not upstream.get("use_proxy"):
        return
    try:
        flow.server_conn.via = EGRESS_PROXY
        flow.metadata["shield_via_proxy"] = True
    except Exception as e:
        # 设不上就照常直连，绝不因此打断转发；但要留痕，否则「代理没生效」无从发现
        _log(f"[egress] 设置出口代理失败 {EGRESS_PROXY}: {type(e).__name__}: {e}")


def _target_miss_reason(host, path):
    path_ok = any(_path_matches(path, p) for p in API_PATHS)
    domain_ok = any(_host_matches(host, d) for d in TARGET_DOMAINS)
    disabled = any(_host_matches(host, off) for off in DOMAINS_DISABLED)
    if disabled:
        return "domain_disabled"
    if not domain_ok:
        return "host_not_configured"
    if not path_ok:
        return "path_not_configured"
    return ""


# 无请求体的方法：直接转发（/v1/models 之类）
_READONLY_METHODS = {"GET", "HEAD", "OPTIONS"}
# LLM 请求体特征键（判断一个 POST 是否值得走脱敏管线）。
# 前 6 个是 OpenAI/Anthropic/Gemini/Responses/Ollama 的标准键；后面几个来自实测漏检：
# Cohere v1 chat 用 message（单数）、Bedrock Titan 用 inputText、讯飞星火用 payload、
# HuggingFace Inference 用 inputs —— 都不在原名单里，整包原文透传
# （SHIELD-SHAPE-WHITELIST-001）。名单只是快速路径，真正的兜底见 request() 里
# 「已配置上游 + fail_closed 一律脱敏」的分支：白名单追不上新协议，不能只靠它。
_LLM_BODY_KEYS = (
    "messages", "prompt", "input", "instructions", "system", "contents",
    "message", "inputText", "inputs", "payload", "chat_history", "query",
    "documents",
)


def _looks_like_llm_request(flow):
    """请求体是否像 LLM 补全请求。用于放行非白名单路径上的非 LLM 调用。"""
    ct = flow.request.headers.get("content-type", "") or ""
    if "json" not in ct:
        return False
    try:
        body = json.loads(flow.request.content)
    except Exception:
        return True  # 声明 JSON 却解析失败，交给主管线按 fail-closed 处理
    return isinstance(body, dict) and any(k in body for k in _LLM_BODY_KEYS)


def _emit_skip(host, method, path, reason, content_type="", source=None, force=False, upstream=""):
    """记录未脱敏/透传类事件。

    规则：
    - 已命中配置的客户端端口（upstream 非空）：每条都记，绝不去重 —— 用户要「过网关必有日志」
    - 未命中路由（no_reverse_route / not_target）：10s 去重，避免乱扫端口刷屏
    - force=True：强制记一条
    """
    global _skip_seen_last_purge
    clean_path = (path or "").split("?", 1)[0]
    src = dict(source or {})
    # 已配置客户端的流量：不去重
    hit_client = bool(upstream) or force
    dedupe = (not hit_client) and reason in {
        "no_reverse_route", "not_target", "host_not_configured", "path_not_configured",
    }
    key = (host, method, clean_path, reason)
    now = time.time()
    if dedupe:
        if now - _skip_seen.get(key, 0) < 10:
            return
        _skip_seen[key] = now
        if now - _skip_seen_last_purge > 30:
            stale = [k for k, ts in _skip_seen.items() if now - ts > 60]
            for k in stale:
                del _skip_seen[k]
            _skip_seen_last_purge = now
    _emit(
        "SKIP" if not hit_client else "PASS",
        host=host,
        method=method,
        path=clean_path,
        reason=reason,
        content_type=str(content_type or "")[:80],
        count=0,
        upstream=upstream or "",
        **src,
    )


def _body_preview(raw, limit=1200):
    """请求/响应体预览（截断、去空白）。绝不包含敏感原文。
    先截断再正则：2MB body 全文空白折叠曾耗时 23ms/请求，截断后只剩 limit 字符。
    截断前必须先存原长，否则折叠后算 len-text 会得到负数（曾显示 …(+N字) 负数）。"""
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        text = raw.decode("utf-8", errors="replace")
    else:
        text = str(raw)
    raw_len = len(text)
    if raw_len > limit:
        text = re.sub(r"\s+", " ", text[:limit]).strip()
        return text + f"…(+{raw_len - limit}字)"
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _msg_text(content):
    """把 message.content（str 或 content blocks）抽成纯文本。"""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for blk in content:
            if isinstance(blk, str):
                parts.append(blk)
            elif isinstance(blk, dict):
                t = blk.get("text") or blk.get("content") or ""
                if isinstance(t, str) and t:
                    parts.append(t)
        return "\n".join(parts)
    return str(content)


def _extract_chat_dialog(raw, limit=4000):
    """从请求/响应 body 抽出「对话内容」便于日志阅读。

    请求：只保留 user/assistant 消息（跳过 system 长指令）。
    响应：JSON choices 或 SSE data 行里的 assistant 文本。
    返回可读纯文本，不是整包 JSON。
    """
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        text = raw.decode("utf-8", errors="replace")
    else:
        text = str(raw)
    text = text.strip()
    if not text:
        return ""

    def _assistant_sections(reasoning_parts=None, content_parts=None):
        """Keep model thinking and final answer separate in the event dialog."""
        sections = []
        thinking = "".join(x for x in (reasoning_parts or []) if isinstance(x, str))
        answer = "".join(x for x in (content_parts or []) if isinstance(x, str))
        if thinking.strip():
            sections.append(f"【助手思考】\n{thinking.strip()}")
        if answer.strip():
            sections.append(f"【助手】\n{answer.strip()}")
        return sections

    # 1) 尝试 JSON 请求/非流式响应
    try:
        body = json.loads(text)
        if isinstance(body, dict):
            lines = []
            # Chat Completions / Messages 请求：按顺序展示全部用户消息。
            # OpenCode 会携带 system prompt 和整段历史：system 指令跳过；
            # 曾只取末条 user——命中常在 system/更早历史，用户看不到自己发送的
            # 内容（SHIELD-DIALOG-001）。总量仍受 limit 截断。
            msgs = body.get("messages")
            if isinstance(msgs, list):
                for m in msgs:
                    if not isinstance(m, dict):
                        continue
                    role = str(m.get("role") or "")
                    if role != "user":
                        continue
                    content = _msg_text(m.get("content"))
                    if content:
                        lines.append(f"【用户】\n{content.strip()}")
            # 非流式响应
            ch = body.get("choices")
            if isinstance(ch, list) and ch:
                c0 = ch[0] if isinstance(ch[0], dict) else {}
                msg = c0.get("message") if isinstance(c0.get("message"), dict) else {}
                content = _msg_text(msg.get("content") if msg else None) or str(c0.get("text") or "")
                reasoning = msg.get("reasoning_content") if msg else None
                if not isinstance(reasoning, str) or not reasoning.strip():
                    reasoning = msg.get("reasoning") if msg else None
                lines.extend(_assistant_sections([reasoning], [content]))
            # Anthropic content
            cont = body.get("content")
            if isinstance(cont, list) and not lines:
                thinking = [b.get("thinking") for b in cont
                            if isinstance(b, dict) and isinstance(b.get("thinking"), str)]
                answer = [b.get("text") for b in cont
                          if isinstance(b, dict) and isinstance(b.get("text"), str)]
                lines.extend(_assistant_sections(thinking, answer))
            if lines:
                out = "\n\n".join(lines)
                if len(out) > limit:
                    return out[:limit] + f"…(+{len(out) - limit}字)"
                return out
    except Exception:
        pass

    # 2) SSE 流式：拼 delta.content
    if "data:" in text or "\ndata:" in text:
        reasoning_buf = []
        content_buf = []
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if not payload or payload == "[DONE]":
                continue
            try:
                obj = json.loads(payload)
            except Exception:
                continue
            if not isinstance(obj, dict):
                continue
            ch = obj.get("choices")
            if isinstance(ch, list) and ch and isinstance(ch[0], dict):
                delta = ch[0].get("delta") if isinstance(ch[0].get("delta"), dict) else {}
                c = delta.get("content") if delta else None
                if isinstance(c, str) and c:
                    content_buf.append(c)
                rc = delta.get("reasoning_content") if delta else None
                if not isinstance(rc, str) or not rc:
                    rc = delta.get("reasoning") if delta else None
                if isinstance(rc, str) and rc:
                    reasoning_buf.append(rc)
                msg = ch[0].get("message") if isinstance(ch[0].get("message"), dict) else {}
                if msg:
                    mc = _msg_text(msg.get("content"))
                    if mc:
                        content_buf.append(mc)
            # Anthropic SSE
            if obj.get("type") == "content_block_delta":
                delta_obj = obj.get("delta")
                delta = delta_obj if isinstance(delta_obj, dict) else {}
                if isinstance(delta.get("thinking"), str):
                    reasoning_buf.append(delta["thinking"])
                if isinstance(delta.get("text"), str):
                    content_buf.append(delta["text"])
            # OpenAI Responses API SSE
            et = obj.get("type")
            if et == "response.output_text.delta" and isinstance(obj.get("delta"), str):
                content_buf.append(obj["delta"])
            elif et == "response.reasoning_text.delta" and isinstance(obj.get("delta"), str):
                reasoning_buf.append(obj["delta"])
        sections = _assistant_sections(reasoning_buf, content_buf)
        if sections:
            out = "\n\n".join(sections)
            if len(out) > limit:
                return out[:limit] + f"…(+{len(out) - limit}字)"
            return out

    # JSON/SSE 能解析但没有对话正文时保持为空；原始协议内容另存 req/resp_preview。
    # 详情默认只展示对话，不能再把 system prompt/整包 SSE 当作对话回退显示。
    if text.startswith("{") or text.startswith("[") or "data:" in text:
        return ""
    return _body_preview(text, min(limit, 800))


def _extract_model(body):
    if not isinstance(body, dict):
        return ""
    m = body.get("model")
    return str(m)[:120] if m else ""


def _rule_enabled(label):
    """内置规则是否启用；缺省 True。"""
    return bool(BUILTIN_RULES.get(label, True))


def _custom_word_enabled(word, label):
    if label in SENSITIVE_DISABLED:
        return False
    disabled_words = SENSITIVE_WORD_DISABLED.get(label) or set()
    if word in disabled_words:
        return False
    return True


# 单字词两侧不能是 CJK/字母数字，避免「密」打中「密码」、「加」打中「加密」。
# 两字及以上仍子串匹配（「张三」左右常是汉字，加 CJK 边界会漏）；两字高频词靠 UI 禁用/默认关控制。
_SINGLE_WORD_BOUND = r"A-Za-z0-9_\u4e00-\u9fff"
# 整词开关用的边界**不含汉字**：汉字之间不存在词边界，`手机` 两侧几乎永远是汉字，
# 用 CJK 做边界等于该词永不命中——实测「开关整词匹配」会把中文词的脱敏整个关掉，
# 且界面上毫无提示（漏脱敏，不是误伤）。无分词器时中文词的「整词」无法表达，
# 退化回子串匹配（宁可多打码，不可漏打码）；ASCII 词边界照旧，Acme 不会命中 AcmeCorp。
_WHOLE_WORD_BOUND = r"A-Za-z0-9_"
_CUSTOM_WORD_RX_CACHE = {}
# 合并正则缓存：500 词 × 10 万字符从 O(词数×长度) 降到 O(长度)（审计性能项）。
# 词表/禁用状态变化时 key 失效重建；key 计算是 O(词数) 的元组比较，微秒级。
_CUSTOM_COMBINED_CACHE = {"key": None, "rx": None}


def _custom_word_regex(word):
    """自定义词匹配：≥2 字子串；单字带边界，降低误伤。

    大小写不敏感（审计规则专项 P2）：加 IGNORECASE，Acme 匹配 ACME/acme。
    防御：超长词（>200 字符）直接返回 None 跳过——
    面板保存时已限长，但 config 可能被手工写入/旧版本遗留，超长词 escape 后
    拖慢合并正则重建与扫描（审计 P1）。
    """
    if not word or len(word) > 200:
        return None
    cached = _CUSTOM_WORD_RX_CACHE.get(word)
    if cached is not None:
        return cached
    esc = re.escape(word)
    if len(word) == 1:
        rx = re.compile(rf"(?<![{_SINGLE_WORD_BOUND}]){esc}(?![{_SINGLE_WORD_BOUND}])", re.IGNORECASE)
    else:
        rx = re.compile(esc, re.IGNORECASE)
    _CUSTOM_WORD_RX_CACHE[word] = rx
    return rx


def _custom_combined_regex():
    """全部启用词合并为一条正则（词按长度降序，同一位置长词优先，与逐词替换语义一致）。

    支持 re: 前缀的正则型自定义词（审计规则专项 P3）：如 re:EMP-\\d{6}。
    正则词不 re.escape，直接拼入合并正则。

    P0 修复（审计意见）：正则词编译保护——用户填的非法正则（缺括号等）
    会 re.compile 抛 PatternError，导致整个合并正则失败 → mask() 异常 →
    fail-closed 503，全部客户端被拒。这里逐词 try 编译，坏词跳过并留痕，
    其余词照常生效；绝不让词表配置错误升级成全局阻断。

    缓存命中判断必须放在构建 parts 之前：合并正则的 key 已完整覆盖词表与禁用状态
    （_custom_word_enabled 只读 SENSITIVE_DISABLED / SENSITIVE_WORD_DISABLED），
    命中时直接返回，既省掉热路径上的排序与拼接，也避免「跳过非法正则词」的日志
    每次请求都重打一遍（原实现把日志与 parts 构建放在检查之前，命中缓存也会刷日志）。
    """
    key = (
        tuple(CUSTOM_WORDS.items()),
        tuple(sorted(SENSITIVE_DISABLED)),
        tuple(sorted((l, w) for l, ws in SENSITIVE_WORD_DISABLED.items() for w in ws)),
        tuple(sorted(SENSITIVE_WORD_WHOLE)),
    )
    if _CUSTOM_COMBINED_CACHE["key"] == key and _CUSTOM_COMBINED_CACHE["rx"] is not None:
        return _CUSTOM_COMBINED_CACHE["rx"]
    parts = []
    skipped = []
    for word, label in _custom_words_sorted():
        if not word or not _custom_word_enabled(word, label):
            continue
        if word.startswith("re:"):
            # 正则型自定义词：单独编译校验，失败跳过（不阻断其他词）
            try:
                re.compile(word[3:], re.IGNORECASE)
            except re.error as e:
                skipped.append((word, str(e)))
                continue
            parts.append(word[3:])
            continue
        esc = re.escape(word)
        if len(word) == 1 or word in SENSITIVE_WORD_WHOLE:
            # 单字词或显式整词开关：两侧加边界，避免子串误伤。
            # 边界字符类分档：单字词用 _SINGLE_WORD_BOUND（含汉字，避免「密」打中
            # 「密码」）；整词开关用 _WHOLE_WORD_BOUND（不含汉字）——否则中文词永不命中，
            # 见该常量处的说明。单字判在前，故单字词的行为未变。
            bound = _SINGLE_WORD_BOUND if len(word) == 1 else _WHOLE_WORD_BOUND
            parts.append(rf"(?<![{bound}]){esc}(?![{bound}])")
        else:
            parts.append(esc)
    if skipped:
        for w, err in skipped[:5]:
            _log(f"[mask] 跳过非法正则词 {w[:60]}...：{err}")
    # 整体再包一层 try：parts 拼合本身也可能因用户正则里的 | 破坏结构，
    # 兜底降级为空正则（全部词不生效但代理不 503）
    try:
        rx = re.compile("|".join(parts), re.IGNORECASE) if parts else None
    except re.error as e:
        _log(f"[mask] 合并正则编译失败，词表降级为空（坏词已跳过）：{e}")
        rx = None
    _CUSTOM_COMBINED_CACHE["key"] = key
    _CUSTOM_COMBINED_CACHE["rx"] = rx
    return rx


def _sync_custom_word_mappings():
    """同步自定义敏感词的永久映射表。

    在启动、热重载或 CUSTOM_WORDS 变动时调用。
    为启用的自定义敏感词生成稳定、跨会话确定性的 6 位纯辅音占位符并永久常驻，
    永不被 TTL 清理或超量淘汰，确保多轮会话或长任务调用工具时稳定还原。
    """
    global _CUSTOM_WORD_FWD, _CUSTOM_WORD_REV
    now = time.time()
    active_words = {}
    for word, label in _custom_words_sorted():
        if word and _custom_word_enabled(word, label):
            active_words[word] = label

    # 清理已从配置中移除或禁用的词
    stale_words = [w for w in list(_CUSTOM_WORD_FWD.keys()) if w not in active_words]
    for w in stale_words:
        tok = _CUSTOM_WORD_FWD.pop(w, None)
        if tok:
            _CUSTOM_WORD_REV.pop(tok, None)

    # 避让集合必须并入**全局后缀索引**（_RECENT_SUFFIX，含规则/NER/历史已签发的活跃
    # token），不能只避让自定义词自己的后缀：否则新词一旦撞上某个活跃 token 的后缀
    # （标签相同时 = 完整 token 相同），下面 `_RECENT_REV[tok] = ...` 会把那个 token
    # 静默改指向新词——换会话 / 会话过期后 restore 会把 A 的原文填到 B 的位置上。
    # 后缀空间 19^6≈4700 万、活跃至多 2000 条，实测约 4.3e-5/词，撞上即静默错值。
    used_suffixes = {
        _token_suffix(tok) for tok in _CUSTOM_WORD_REV
    } | set(_RECENT_SUFFIX)
    for word, label in active_words.items():
        if word in _CUSTOM_WORD_FWD:
            tok = _CUSTOM_WORD_FWD[word]
            old_label = _CUSTOM_WORD_REV.get(tok, [None, None])[1]
            if old_label == label and _safe_label(old_label) == _safe_label(label):
                if tok in _CUSTOM_WORD_REV:
                    _CUSTOM_WORD_REV[tok][2] = now
                continue
            # 标签变更时注销旧 token，重新派生
            _CUSTOM_WORD_REV.pop(tok, None)
            _RECENT_REV.pop(tok, None)
            _suffix_index_del(tok)

        suffix = _deterministic_suffix(word, used_suffixes)
        used_suffixes.add(suffix)
        lab = _safe_label(label)
        tok = "{{%s_%s}}" % (lab, suffix)
        prev = _RECENT_FWD.get(word)
        if prev and prev[0] != tok:
            # 预热/历史带进来的旧 token：换新 token 后必须注销，否则它会留在
            # REV 与后缀索引里长驻成孤儿（_prune_recent 只按 FWD 扫，碰不到）
            _RECENT_REV.pop(prev[0], None)
            _suffix_index_del(prev[0])
        _CUSTOM_WORD_FWD[word] = tok
        _CUSTOM_WORD_REV[tok] = [word, label, now]
        _RECENT_FWD[word] = [tok, label, now]
        _RECENT_REV[tok] = [word, label, now]
        _suffix_index_add(tok)


def _request_scope(body):
    """请求扫描范围摘要（只含计数，不落原文）。说明日志 dialog 为何可能远少于 count。"""
    scope = {
        "msg_count": 0,
        "roles": {},
        "has_system": False,
        "has_tools": False,
        "latest_user_len": 0,
        "scan": "full_body",  # 当前策略：messages/system/tools 等全量递归脱敏
    }
    if not isinstance(body, dict):
        return scope
    msgs = body.get("messages")
    if isinstance(msgs, list):
        scope["msg_count"] = len(msgs)
        for m in msgs:
            if not isinstance(m, dict):
                continue
            role = str(m.get("role") or "other") or "other"
            scope["roles"][role] = scope["roles"].get(role, 0) + 1
            if role == "system":
                scope["has_system"] = True
            if role in ("tool", "function"):
                scope["has_tools"] = True
        for m in reversed(msgs):
            if isinstance(m, dict) and str(m.get("role") or "") == "user":
                t = _msg_text(m.get("content")) or ""
                scope["latest_user_len"] = len(t)
                break
    if body.get("system"):
        scope["has_system"] = True
        scope["roles"]["system"] = scope["roles"].get("system", 0) + 1
    if body.get("tools") or body.get("functions"):
        scope["has_tools"] = True
    for key in ("prompt", "input", "instructions", "contents"):
        if key in body and body[key] not in (None, "", [], {}):
            scope["roles"][key] = scope["roles"].get(key, 0) + 1
    return scope


def _collect_role_texts(body):
    """脱敏前各角色/字段文本，用于命中归因（仅内存，不写日志原文）。

    用 list 累积再 join，避免 += 字符串拼接的 O(n²) 复制（大 body 会话历史可上百 KB）。
    """
    bags = {}

    def add(role, text):
        if not isinstance(text, str) or not text:
            return
        bags.setdefault(role, []).append(text)

    if not isinstance(body, dict):
        return {k: "\n".join(v) for k, v in bags.items()}
    msgs = body.get("messages")
    if isinstance(msgs, list):
        for m in msgs:
            if not isinstance(m, dict):
                continue
            role = str(m.get("role") or "other") or "other"
            add(role, _msg_text(m.get("content")))
            # tool_calls / function_call 参数常带历史真实值
            for tc in m.get("tool_calls") or []:
                if not isinstance(tc, dict):
                    continue
                fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
                args = fn.get("arguments")
                if isinstance(args, str):
                    add("tool", args)
            fc = m.get("function_call")
            if isinstance(fc, dict) and isinstance(fc.get("arguments"), str):
                add("tool", fc["arguments"])
    for key in ("system", "prompt", "instructions"):
        v = body.get(key)
        if isinstance(v, str):
            add(key if key != "system" else "system", v)
        elif isinstance(v, list):
            add(key, _msg_text(v))
    inp = body.get("input")
    if isinstance(inp, str):
        add("input", inp)
    elif isinstance(inp, list):
        for part in inp:
            if isinstance(part, str):
                add("input", part)
            elif isinstance(part, dict):
                add(str(part.get("role") or "input"), _msg_text(part.get("content")))
    return {k: "\n".join(v) for k, v in bags.items()}


def _hit_roles_for(orig, role_texts):
    if not orig or not role_texts:
        return []
    hit = []
    for role, text in role_texts.items():
        if orig in text:
            hit.append(role)
    return hit


# ===== 占位符后缀字符集（0.1.13 起改用纯辅音，旧的 hex6 仍然认） =====
#
# 起因：模型会把 hex 后缀当成可以做算术的数。实测生产库 8798 条 RESTORE 里
# 36 条（0.41%）有占位符没还原，其中 92/97 是 IPPRIVATE——模型看到
# {{IPPRIVATE_83fc6a}}（对应 192.168.119.5），把 83fc 当网段前缀、6a 当主机位，
# 于是自己造出 {{IPPRIVATE_83fc00}} 表示子网、{{IPPRIVATE_83fc02}} 表示网关。
# 这两个 token 我们从没签发过，还原不了，也绝不许猜（见 _lookup 的长注释）。
#
# 六位十六进制**长得就是一个能拆开计算的数**，这是诱因本身。换成纯辅音后
# 后缀没有任何数值可读性，模型没有「改后缀」这个动作可做。
# 注意这只降低诱因，不构成保证——真出现了仍然走 unresolved 如实上报。
#
# 为什么是辅音而不是全字母：
# - _LOOSE_PLACEHOLDER_RX 是**不带花括号**匹配的（模型常把 {{}} 剥掉）。若放宽成
#   [0-9a-z]{6}，`HTTP_status` / `MAX_buffer` 这类代码标识符会命中，每次白查一次表。
#   辅音表不含 aeiou，天然与英文单词不相交（status 含 a、u，匹配不上）。
# - 去掉 l/i/o 是因为与 1/0 形近，模型复述时容易串。
# 熵：19^6 ≈ 4700 万 > hex6 的 1677 万，冲突概率反而更低。
_TOKEN_ALPHABET = "bcdfghjkmnpqrstvwxz"
# 新旧后缀的并集。写并集而不是放宽字符类：存量占位符（客户端历史对话里、
# 事件库预热回来的）全是 hex6 必须继续认，同时不把匹配面扩到英文单词。
_SUFFIX_PAT = r"(?:[0-9a-f]{6}|[bcdfghjkmnpqrstvwxz]{6})"

# 完整占位符 / 行尾半截占位符（流式时可能被切在两个 chunk 之间）
_PLACEHOLDER_RX = re.compile(r"\{\{[A-Z0-9]{1,12}_" + _SUFFIX_PAT + r"\}\}")
# 兼容内部空白与标签改写的双花括号占位符（用于还原时的容错第一遍）
# 覆盖模型习惯在 {{ 与标签之间加空格（如 Jinja 语法风格 `{{ APIKEY_xxxx }}`），
# 避免原先按宽松正则替换导致留下 `{{ ` 和 ` }}` 破坏工具命令。
_BRACED_PLACEHOLDER_RX = re.compile(
    r"\{\{\s*([A-Za-z0-9_]{1,12})_(" + _SUFFIX_PAT + r")\s*\}\}"
)
# 「裸露 / 半残」占位符：模型经常把 {{ }} 剥掉或只剩一半再吐回来。
#
# 实测（deepseek-v4-flash，真实调用）：让它把脱敏后的 token 拼进一条 curl，
# 输出是 `X-Setup-Token: SECRET_b5a53c` —— 花括号没了。原因很直白：
# {{...}} 在 Jinja/Handlebars/Vue 里就是模板语法，模型写命令时会顺手"整理"掉。
# 严格正则匹配不到 → 整个还原被跳过 → 用户拿到一个假 token 去执行。
#
# 这条只做兜底修复，且**只替换我们自己发过的 token**（必须能在会话/复用表里查到），
# 所以不存在误伤：LABEL_后缀 这种组合（6 位纯辅音或存量 hex6）正常文本里不会自然出现，何况还要求查得到。
_LOOSE_PLACEHOLDER_RX = re.compile(
    r"\{{1,2}\s*([A-Za-z0-9_]{1,12}_" + _SUFFIX_PAT + r")\s*\}{0,2}|([A-Z0-9]{1,12}_" + _SUFFIX_PAT + r")"
)
# 行尾半截占位符（流式时可能被切在两个 chunk 之间），需要扣住等下一块拼。
#
# 反斜杠必须进入缓冲范围：模型输出 `\{\{X\}\}` 时，chunk 边界可能正好落在
# 反斜杠与花括号之间（实测：不认反斜杠时 32 个切点里有 23 个会漏出 `\{\` 残渣，
# 因为第一个 chunk 只被扣下 `{`、反斜杠已经发出去了）。反斜杠必须和花括号
# 一起扣住才拼得回来。
#
# 花括号那一段必须写成 `(?:\\{0,3}\{){1,3}`，与 _ESCAPED_PLACEHOLDER_RX 同构：
# 两个花括号之间也夹着反斜杠（`\ { \ {`），写成 `\{\{?` 只能从内层花括号开始
# 匹配，外层反斜杠照样漏出去。
#
# **无上限的反斜杠量词必须封顶**（`\\*`→`\\{0,3}`、`\\+`→`\\{1,3}`）：否则本正则
# 在「连续反斜杠、末尾又不是反斜杠」的文本上会退化成 O(N²) 回溯。实测 8192 个
# 反斜杠：第一分支 `(?:\\*\{){1,3}...` 耗时 20ms，封顶后 0.12ms；`\\+$` 分支
# 耗时 133ms，封顶后 0.14ms —— **`\\+$` 才是主因**（无上限的 `\\+` 在每个非末尾
# 位置都要逐次回吐，每位置 O(N)）。封顶后整条正则为线性。
# 真实转义形态最多 3 个反斜杠（`\\\{\\\{`），3 够用；`\\{1,3}$` 与 `\\+$` 语义
# 等价（search 从最左成功位置开始），只是扣留范围由「全部反斜杠」收窄为
# 「末尾 1~3 个」—— 4 层以上转义不存在，收窄无影响。
#
# 末尾那个 `\\{1,3}$` 分支单独列出，是为了「切点正好落在反斜杠与花括号之间」：
# 此时 chunk 以裸反斜杠结尾，看不出来它后面要跟花括号，只能先扣住。代价是
# 普通文本里以反斜杠结尾的 chunk（Windows 路径 `C:\Users\`、行继续符）也会
# 多扣一个 chunk —— 内容不会丢，下一块或收尾时照常发出，只是晚一个 chunk。
# 换来的是转义形态在**全部 32 个切点**上都还原干净（不扣反斜杠时实测 23 个
# 切点会漏残渣，扣了之后为 0）。
#
# `{` 本身仍然是必需的——所以不含花括号的普通文本（`C:\Users\` 之外，
# 比如「今天天气」）不会被扣住。
_PARTIAL_RX = re.compile(r"(?:\\{0,3}\{){1,3}\s{0,4}[A-Za-z0-9_]{0,20}\s{0,4}\\{0,3}\}?\\{0,3}$|\\{1,3}$")
# 扣留上限：必须 ≥ _PARTIAL_RX 能匹配出的最长片段，否则「扣不下」会退化成
# 「就地处理半截占位符」——比如此前是 24，而二次转义的完整片段长 25，
# 于是它总是不被扣留、还原后留下 `\\}` 残渣。
# 反斜杠与空白都封顶后，模式的理论上限 = 3 单元×4 + 4 + 20 + 4 + (3+1+3) = 47，
# 故放到 48。空白原是无界 `\s*`，那样「理论最长」根本无从计算，扣留上限也就
# 失去依据（`{{` 后跟 40+ 空白的半截块扣不下，退化成留残渣）。
# 保持小而具体：只是「一段疑似半截占位符」，不是缓冲任意文本。
_PARTIAL_MAX = 48
# 从完整占位符里拆出 label 与后缀。多处要用，别再各写各的正则——
# 0.1.12 就有三处各自写死 [0-9a-f]{6}，改格式时漏一处就是静默失效。
_PLACEHOLDER_PARTS_RX = re.compile(r"^\{\{([A-Z0-9]{1,12})_(" + _SUFFIX_PAT + r")\}\}$")
# 转义形态：模型把 {{ }} 当成需要转义的字符，输出 \{\{X\}\}。
#
# 反斜杠要允许「每个花括号前后都有、且不止一个」，两个原因都是实测/推演出来的：
# - 反斜杠在**每个**花括号前后都要允许：真实输入是 `\ { \ { X \ } \ }`，两个
#   花括号**之间也夹着反斜杠**，`(?:\\)?\{\{(?:\\)?(...)` 这种写法连门都进不去；
# - 模型还会二次转义（`\\{\\{X\\}\\}`，它在按 JSON 的规则思考），只允许一个
#   反斜杠会剩下 `\\{\\` 残渣 —— 与不修没区别。
#
# 量词写成 `\\{0,3}` 而不是 `\\*`：**上限本身就是性能要求**。`\\*` 无上限时，
# 在「连续反斜杠、后面并没有花括号」的文本上，每个起始位置都要把剩余的反斜杠
# 全部回吐一遍才失败 → O(N²)。实测（N 个反斜杠 + 一个下划线）：
# 1024→0.30ms、4096→4.57ms、8192→18.2ms、16384→72.9ms、32768→293ms；
# 封顶后 0.013 / 0.052 / 0.105 / 0.224 / 0.405ms，线性。
# 3 足够（真实转义最多两层 `\\{\\{`），且 _PARTIAL_RX 取同一个上限，
# 两遍对同一形态的判定才不会错位。
#
# 花括号组写成 `{1,3}` 而不是 `{1,2}`：流式还原时 _PARTIAL_RX 会把行尾的裸
# 反斜杠也扣住（否则切点落在反斜杠与花括号之间就漏残渣），于是下一块拼起来的
# 文本可能多带一层反斜杠/花括号，这里要能容忍。
#
# 已知代价（写在这里以免日后当成 bug 追）：反斜杠紧贴在占位符左侧时会被一并
# 吃掉，所以「Windows 路径分隔符 + 标签被改写过的占位符」这种组合会少一个 `\`。
# 常规形态（标签完好）由严格遍先处理，走不到这里，所以暴露面很窄；而且一旦
# 查不到原文就原样放回，不会误吃。
#
# 与 _LOOSE_PLACEHOLDER_RX 的分工：这一条**必须带花括号**，因此只用在严格遍
# 与转义遍；不带花括号的形态仍交给宽松正则，且宽松正则不许走后缀索引
# （理由见 _RECENT_SUFFIX 的注释）。
_ESCAPED_PLACEHOLDER_RX = re.compile(
    r"(?:\\{0,3}\{){1,3}(?:\\{0,3})\s*([A-Za-z0-9_]{1,12})_(" + _SUFFIX_PAT + r")\s*(?:\\{0,3}\}){1,3}",
    re.IGNORECASE,
)
# 从「带花括号但标签可能被改写」的形态里取后缀。标签允许含下划线：
# 模型会自己把 `IPPRIVATE` 补成 `IP_PRIVATE`，用 _PLACEHOLDER_PARTS_RX
# （标签字符类不含下划线）解析不了这种。
_ANY_BRACED_SUFFIX_RX = re.compile(
    r"^\{\{\s*([A-Za-z0-9_]{1,12})_(" + _SUFFIX_PAT + r")\s*\}\}$", re.IGNORECASE
)


def _token_suffix(token):
    """取 token 的 6 位后缀（小写）；形态不对返回空串。

    用字符串切分而不是正则：`{{LABEL_suffix}}` 里 label 由 _safe_label 保证
    不含下划线，所以最后一个下划线之后就是后缀；对模型改写过的
    `{{IP_PRIVATE_x}}` 同样成立。
    """
    if not isinstance(token, str) or not token.startswith("{{") or not token.endswith("}}"):
        return ""
    body = token[2:-2].strip()
    if "_" not in body:
        return ""
    return body.rsplit("_", 1)[1].lower()


def _token_label(token):
    """取 token 的标签部分（原样，未归一化）；形态不对返回空串。"""
    if not isinstance(token, str) or not token.startswith("{{") or not token.endswith("}}"):
        return ""
    body = token[2:-2].strip()
    if "_" not in body:
        return ""
    return body.rsplit("_", 1)[0]


def _suffix_indexable(suffix):
    """该后缀是否允许进索引：必须 6 位纯辅音。

    hex6 后缀不进索引，原因见 _RECENT_SUFFIX 注释（代码里 `_abc123` 太常见，
    进索引就会误替换）。
    """
    return len(suffix) == 6 and all(c in _TOKEN_ALPHABET for c in suffix)


def _suffix_index_add(token):
    """登记后缀索引。**撞车即置为不可用，绝不覆盖、也绝不保留其一。**

    新 token 由 _new_token 保证后缀不与索引冲突，所以撞车只可能来自事件库
    预热/客户端历史带进来的历史 token。无论保留哪一个，都会让「按后缀反查」
    把 A 的原文答到 B 的位置上，所以撞车后该后缀直接退出兜底匹配——代价只是
    这个后缀不参与兜底，退化成改动前的行为。**替换错值比不替换危险得多。**

    **必须值比较（!=），不能对象身份比较（is not）**：预热走 json.loads、
    客户端历史走 sqlite 取出，拿到的 token 与索引里已存的那个**值相等但对象
    不同**。用 `is not` 会让「同一个 token 被登记两次」被误判成撞车，后缀
    永久退出兜底（且运行时补登记救不回来，见 _recall_token）。实测：预热里
    同一 token 出现 ≥2 条事件是常态（复用表的设计目的就是跨请求复用），
    于是大面积静默失效、用户只看到占位符没被还原。
    """
    sfx = _token_suffix(token)
    if not _suffix_indexable(sfx):
        return
    cur = _RECENT_SUFFIX.get(sfx)
    if cur is None:
        _RECENT_SUFFIX[sfx] = token
    elif cur != token:
        # _SUFFIX_AMBIGUOUS 是 object()，与任何字符串 != 恒真 -> 撞车标记不会被
        # 后续登记抹掉；真撞车（两个不同 token 抢同一后缀）的语义不变。
        _RECENT_SUFFIX[sfx] = _SUFFIX_AMBIGUOUS


def _suffix_index_del(token):
    """注销后缀索引。只删「确实指向本 token」的条目。

    撞车标记不会被删：它本来就不指向任何具体 token，而恢复成「指向剩下的那个」
    又会重新引入歧义。撞车只在预热历史数据时可能发生（新 token 已保证后缀唯一），
    条数极少，留着不影响内存。
    """
    sfx = _token_suffix(token)
    if sfx and _RECENT_SUFFIX.get(sfx) == token:
        _RECENT_SUFFIX.pop(sfx, None)


def _suffix_real_token(token):
    """按后缀反查出**真实签发的 token**；不满足全部条件返回 None。

    与 _lookup_by_suffix 拆开，是为了让调用方能拿到真实 token 去做记账
    （restored_tokens 里存的是签发时的原 token，不是模型改写后的形态）。

    调用点必须**已经保证 token 带花括号**（严格遍与转义遍）。裸 token 不许
    走这里：流式响应里它可能只是被 chunk 切开的残片（实测 `ATE_zwndfk`），
    按后缀命中后会把残片替换成明文，拼出一条错的命令。

    **标签必须归一化后相等才认**（`_safe_label` 去大小写、去下划线）：
    - `{{IP_PRIVATE_x}}` / `{{ipprivate_x}}` → 归一到 `IPPRIVATE`，命中；
    - `{{HOST_x}}` → `HOST` != `IPPRIVATE`，**拒绝**，原样放回并计入 unresolved。

    为什么不做「只看后缀、标签随便」的完全宽松匹配：后缀虽然只有 47M 分之一
    的碰撞概率，但一旦碰撞就是**把 A 的原文（真实内网 IP、手机号）替换到 B 的
    位置上**，属于静默替换错值。而拒绝的代价只是「这次没救回来」，用户能看见
    裸占位符、命令失败得明明白白。宁可失败可见，不可静默替换——与 _lookup
    「不做模糊匹配、不猜」的既有约定一致。
    """
    m = _ANY_BRACED_SUFFIX_RX.match(token)
    if not m:
        return None
    real = _RECENT_SUFFIX.get(m.group(2).lower())
    if not isinstance(real, str) or real == token:
        # None = 没登记过；_SUFFIX_AMBIGUOUS = 该后缀撞车、已退出兜底；
        # real == token 说明精确路径刚查过且落空，再查一次没意义
        return None
    if _safe_label(m.group(1)) != _safe_label(_token_label(real)):
        return None
    return real


def _lookup_by_suffix(token, sid):
    """按后缀反查原文（容错路径）。判定逻辑见 _suffix_real_token。"""
    real = _suffix_real_token(token)
    if real is None:
        return None
    return _lookup(real, sid)


class Edit(NamedTuple):
    """一次「原文 → 占位符」替换，坐标为**该次替换发生时**的文本坐标系。"""
    start: int      # 闭
    end: int        # 开
    token: str      # 替换后的占位符（部分替换时仅为替换捕获组的占位符）


def _mask_excluding_placeholders_ed(text, rx, sub_fn, group_idx=0):
    """同 _mask_excluding_placeholders，额外返回本次替换产生的 Edit 列表。

    Edit 坐标为**入参 text 的坐标系**（即本趟开始时的坐标系）。
    对 text 做正则替换，但跳过已有的占位符片段（防污染）。
    """
    if not text:
        return text, []

    edits = []
    result = []
    last_end = 0

    def _process_chunk(chunk, base):
        chunk_out = []
        c_last = 0
        for m in rx.finditer(chunk):
            repl = sub_fn(m)
            chunk_out.append(chunk[c_last:m.start()])
            chunk_out.append(repl)
            c_last = m.end()
            if repl != m.group(0):
                if group_idx == 0:
                    edits.append(Edit(base + m.start(), base + m.end(), repl))
                else:
                    gs, ge = m.span(group_idx)
                    prefix_len = gs - m.start()
                    suffix_len = m.end() - ge
                    tok = repl[prefix_len:len(repl) - suffix_len] if suffix_len else repl[prefix_len:]
                    edits.append(Edit(base + gs, base + ge, tok))
        chunk_out.append(chunk[c_last:])
        return "".join(chunk_out)

    for m in _PLACEHOLDER_RX.finditer(text):
        before = text[last_end:m.start()]
        if before:
            result.append(_process_chunk(before, last_end))
        result.append(m.group())
        last_end = m.end()

    tail = text[last_end:]
    if tail:
        result.append(_process_chunk(tail, last_end))

    if not edits and last_end == 0:
        return text, []

    return "".join(result), edits


def _mask_excluding_placeholders(text, rx, sub_fn, group_idx=0):
    """对 text 做正则替换，但跳过已有的占位符片段（防污染）。

    薄封装：转调 _mask_excluding_placeholders_ed 并丢弃 edits。
    """
    new_text, _ = _mask_excluding_placeholders_ed(text, rx, sub_fn, group_idx=group_idx)
    return new_text


# ── NER（语义实体识别）辅助 ───────────────────────────────────────────────────
# NER 是概率模型，与上面那套确定性规则之间有三条硬边界：
#   1. 必须排在确定性规则之后跑，同一原文以确定性命中为准；
#   2. 只能**按区间**替换，且与已有占位符相交时只脱敏「非占位符片段」；
#   3. 长度上限 / 时间预算 / 失败可见性由 ner_engine 负责（见该模块头部成本模型）。
# 先前的实现在这里踩了两个坑（均实测复现，2026-09-19）：
#   - `not _PLACEHOLDER_RX.search(orig)` 守卫是**整段丢弃**：多轮历史带回的占位符
#     会把同一实体（含其中的明文）整段放过；
#   - 用 `re.compile(re.escape(orig))` 做**全文子串替换**：实体在长文本里出现 N 次
#     就扫 N 遍全文（10 万字符实测 69 秒），而这段跑在 mitmproxy 的 asyncio 事件
#     循环上，会冻结全部 upstream 端口的连接。
_NER_WARNED = set()


def _ner_warn_once(key, msg):
    """NER 的失败必须可见（静默降级等于「以为开了、其实没脱」），但同类只记一次。"""
    try:
        import ner_engine
        if hasattr(ner_engine, "record_skip"):
            ner_engine.record_skip(key, msg)
    except Exception:
        pass
    if key in _NER_WARNED:
        return
    _NER_WARNED.add(key)
    try:
        _log(f"[transparent] {msg}")
    except Exception:
        pass


@contextlib.contextmanager
def _ner_doc_budget(seconds):
    """给一段连续调用（如整份 Office 文档逐 run 脱敏）设 NER 总预算。

    单条短文本实测约 10ms，几千个 run 会线性堆到分钟级，而扩展侧 HTTP 超时更短，
    用户看到的就是「文件没脱敏」。超预算后只停用语义识别，确定性规则照常生效。
    """
    try:
        import ner_engine
    except Exception:
        yield
        return
    ner_engine.begin_budget(seconds)
    try:
        yield
    finally:
        ner_engine.end_budget()


def _mask_by_spans(text, spans):
    """按 [start, end, repl) 区间一次性重建文本（spans 须已按 start 排序）。

    重叠区间安全契约：
    - 若出现区间重叠（start < cursor），后续重叠区间必须整段丢弃（continue）。
    - 绝不能将重叠区间截断为 [cursor, end) 替换，因为 repl 绑定的完整原文在还原
      (restore) 时会将前序已覆盖的明文重复吐出，导致文本严重错位与破坏性重复。
    - 上游实体抽取层（ner_engine / _ner_entity_spans）负责确保实体区间两两不交。
    """
    if not spans:
        return text
    out = []
    cursor = 0
    for start, end, repl in spans:
        if start < cursor:
            continue          # 与已接受区间重叠：整段跳过，防错位且防还原重复吐字
        out.append(text[cursor:start])
        out.append(repl)
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


class OffsetMap:
    """由有序、互不重叠的 Edit 序列构造的单调坐标映射。

    记录「存活区间」：src 上未被替换的区间 → 目标上的对应起点。
    kept = [(src_start, src_end, dst_start), ...]，按 src_start 升序。
    """

    def __init__(self, edits=None, src_len=0, kept=None, dst_len=None):
        self.src_len = src_len
        if kept is not None:
            self.kept = kept
            self.dst_len = dst_len if dst_len is not None else (
                kept[-1][2] + (kept[-1][1] - kept[-1][0]) if kept else 0
            )
            self.edits = edits or []
            return

        self.edits = sorted(edits, key=lambda x: x[0]) if edits else []
        kept = []
        cs = cd = 0
        for s, e, tok in self.edits:
            if s < 0 or e < s:
                raise ValueError(f"Edit 区间非法: [{s}, {e}) 必须满足 0 <= start <= end")
            if s < cs:
                raise ValueError(f"Edit 重叠: [{s}, {e}) 与前序边界 {cs} 冲突")
            if s > cs:
                kept.append((cs, s, cd))
                cd += s - cs
            cd += len(tok)
            cs = e
        if cs > src_len:
            raise ValueError(f"Edit 越界: 结束位置 {cs} 超过 src_len {src_len}")
        if cs < src_len:
            kept.append((cs, src_len, cd))
            cd += src_len - cs
        self.kept = kept
        self.dst_len = cd

    def _seg_of(self, i):
        """返回包含 i 的存活区间下标；i 落在被替换区间内则返回 None。"""
        lo, hi = 0, len(self.kept) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            a, b, d = self.kept[mid]
            if i < a:
                hi = mid - 1
            elif i >= b:
                lo = mid + 1
            else:
                return mid
        return None

    def map_point(self, i):
        """i 落在存活区间内 → 返回目标坐标；落在被替换区间内 → 返回 None。"""
        seg = self._seg_of(i)
        if seg is None:
            return None
        a, b, d = self.kept[seg]
        return d + (i - a)

    def map_range(self, s, e):
        """区间映射：两端向内收敛到最近的可定位点。

        起点落在替换区间内 → 向右找到下一个存活区间的起点；
        终点落在替换区间内 → 向左找到上一个存活区间的终点。
        收敛后 s2 >= e2 表示该区间已被完全吃掉 → 返回 None。
        """
        if s >= e:
            return None
        # 起点：第一个 >= s 的存活字符
        lo, hi = 0, len(self.kept) - 1
        seg_s = None
        while lo <= hi:
            mid = (lo + hi) // 2
            a, b, d = self.kept[mid]
            if b <= s:
                lo = mid + 1
            elif a >= e:
                hi = mid - 1
            else:
                seg_s = mid
                hi = mid - 1
        if seg_s is None:
            return None
        a, b, d = self.kept[seg_s]
        s2 = d + (max(s, a) - a)

        # 终点：最后一个 < e 的存活字符
        lo, hi = 0, len(self.kept) - 1
        seg_e = None
        while lo <= hi:
            mid = (lo + hi) // 2
            a, b, d = self.kept[mid]
            if a >= e:
                hi = mid - 1
            elif b <= s:
                lo = mid + 1
            else:
                seg_e = mid
                lo = mid + 1
        if seg_e is None:
            return None
        a, b, d = self.kept[seg_e]
        e2 = d + (min(e, b) - a)
        if e2 <= s2:
            return None
        return s2, e2

    def compose(self, next_om):
        """合成 self (src->mid) 与 next_om (mid->dst)，返回总映射 (src->dst)。

        双指针扫描两者的存活区间交集，时间复杂度 O(len(self.kept) + len(next_om.kept))。
        """
        if self.dst_len != next_om.src_len:
            raise ValueError(f"OffsetMap 尺寸不匹配无法合成: {self.dst_len} vs {next_om.src_len}")
        kept1 = self.kept
        kept2 = next_om.kept
        new_kept = []
        i1 = i2 = 0
        while i1 < len(kept1) and i2 < len(kept2):
            s0, e0, d1 = kept1[i1]
            t1_start = d1
            t1_end = d1 + (e0 - s0)

            s1, e1, d2 = kept2[i2]
            t2_in_start = s1
            t2_in_end = e1

            inter_s = max(t1_start, t2_in_start)
            inter_e = min(t1_end, t2_in_end)

            if inter_s < inter_e:
                new_s0 = s0 + (inter_s - t1_start)
                new_e0 = s0 + (inter_e - t1_start)
                new_d2 = d2 + (inter_s - t2_in_start)
                new_kept.append((new_s0, new_e0, new_d2))

            if t1_end < t2_in_end:
                i1 += 1
            elif t2_in_end < t1_end:
                i2 += 1
            else:
                i1 += 1
                i2 += 1

        return OffsetMap(src_len=self.src_len, kept=new_kept, dst_len=next_om.dst_len)

    @classmethod
    def empty(cls, length):
        """构造恒等映射（无任何编辑）。"""
        return cls([], length)


def _ner_entity_spans(text, entities):
    """把 NER 实体转成可安全替换的区间列表 [(start, end, label), ...]。

    实体与已有占位符相交时，只取**不在占位符内**的片段，并按占位符边界切开：
    - 模型常把 `上海市浦东新区{{TERM_x}}世纪大道100号` 识别成一个地址。整段替换会把
      明文片段与既有占位符混成一个新 token；整段丢弃则明文照原样出网。
      切成两段分别打码，才既不丢保护、也不污染已有占位符。
    - 被占位符切碎的残渣（如 `{` / `}}`）不是实体：片段 strip 后不足 2 字即放弃。
    """
    ph = [(m.start(), m.end()) for m in _PLACEHOLDER_RX.finditer(text)]
    spans = []
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        try:
            start = int(ent["start"])
            end = int(ent["end"])
        except (KeyError, TypeError, ValueError):
            continue
        label = str(ent.get("type") or "TERM")
        if end - start < 2 or start < 0 or end > len(text):
            continue
        cursor = start
        for ps, pe in ph:
            if pe <= cursor:
                continue
            if ps >= end:
                break
            if ps > cursor:
                spans.append((cursor, min(ps, end), label))
            cursor = max(cursor, pe)
            if cursor >= end:
                break
        if cursor < end:
            spans.append((cursor, end, label))
    return spans


def mask(text, sid):
    """脱敏文本。返回脱敏后的文本。

    命中明细通过会话的 last_hits 暴露（本次实际替换的唯一原文，含复用项），
    供 MASK 事件的 count/new_count 统计——count 是会话累计 fwd 大小，会随历史
    增长到几千，直接当「本次脱敏数」展示会误导（用户曾质疑脱敏几千还原几十）。
    """
    if not text:
        return text
    original = text
    om = OffsetMap.empty(len(original)) if NER_ENABLED else None
    om_broken = False

    def _update_om(edits, curr_len):
        nonlocal om, om_broken
        if om is None or om_broken or not edits:
            return
        try:
            om = om.compose(OffsetMap(edits, curr_len))
        except Exception as e:
            om_broken = True
            om = None
            _ner_warn_once("om_compose",
                           "OffsetMap 坐标合成降级，本次跳过 NER 识别: %s: %s"
                           % (type(e).__name__, e))

    s = sessions.get(sid)
    if s is None:
        _new_session(sid)
        s = sessions[sid]
    fwd = s["fwd"]
    labels = s["labels"]
    rev = s["rev"]
    hit_orig = set()
    # 本次请求新增的原文（_remember 之前 fwd 里没有的）；用于 new_count 统计。
    # 注意必须在 _remember 之前判断，否则恒为 0（曾因先写 fwd 再判导致死代码）
    new_orig = set()

    def _hit(orig, label="API_KEY"):
        if orig not in fwd:
            new_orig.add(orig)
            if _remember(fwd, labels, orig, label):
                s["suffix_reused"] = True
            # rev 增量维护：只有新增才补一条，避免每次 mask 全量重建（长会话 fwd 数千条）
            rev[fwd[orig]] = orig
        hit_orig.add(orig)

    # Key 前缀命中归 API_KEY；可被 builtin_rules.API_KEY 关闭
    if _rule_enabled("API_KEY"):
        prefix_rx = _prefix_secret_regex()
        if prefix_rx:
            def _prefix_sub(m):
                orig = m.group()
                _hit(orig)
                return fwd.get(orig, orig)
            # 跳过已有占位符片段（防污染：多轮对话历史里带旧占位符）
            curr_len = len(text)
            text, edits = _mask_excluding_placeholders_ed(text, prefix_rx, _prefix_sub)
            _update_om(edits, curr_len)

    cw_rx = _custom_combined_regex()
    if cw_rx:
        # 单次扫描替换全部自定义词（长词优先，与旧逐词循环语义一致但 O(长度)）
        # 跳过已有占位符片段（防污染：自定义词含 hex 子串会劈开占位符）
        # 大小写不敏感（IGNORECASE）：ACME/acme/Acme 都匹配，但 CUSTOM_WORDS 的 key
        # 可能是 Acme —— 用小写反查 label，避免大小写变体拿不到 label 回退到 TERM。
        _cw_label_lower = {w.lower(): lbl for w, lbl in CUSTOM_WORDS.items()}
        def _cw_sub(m):
            word = m.group(0)
            label = _cw_label_lower.get(word.lower(), "")
            # _hit 需要原始 key 来建 fwd 映射；大小写变体统一用查到的原始 key
            orig_key = next((k for k in CUSTOM_WORDS if k.lower() == word.lower()), word)
            _hit(orig_key, label)
            return fwd.get(orig_key, word)
        curr_len = len(text)
        text, edits = _mask_excluding_placeholders_ed(text, cw_rx, _cw_sub)
        _update_om(edits, curr_len)

    # 被豁免的连接串**区间** [start, end)（end 即 userinfo 结尾的 `@` 之后）：
    # RULES 里 CONNSTR 排在 EMAIL 之前，本列表用于让 EMAIL 避开与这些区间重叠的
    # 命中，否则「口令尾@host」会被当邮箱吃掉、留下口令半明文。
    exempt_conn = []

    for rx, label, group_idx in RULES:
        if not _rule_enabled(label):
            continue
        if not _rule_may_hit(text, label):
            continue  # 特征预检：不含必含特征，跳过整条规则扫描
        matched = []
        for m in rx.finditer(text):
            orig = m.group(group_idx)
            if label == "CARD" and not _card_ok(orig):
                continue
            if label == "IDCARD" and not _idcard_ok(orig):
                continue
            if label == "PHONE" and not _phone_ok(orig):
                continue
            if label == "LANDLINE" and not _landline_ok(orig):
                continue
            if label == "EMAIL" and not _email_ok(orig):
                continue
            if label == "IBAN" and not _iban_ok(orig):
                continue
            if label == "JWT" and not _jwt_ok(orig):
                continue
            if label == "IP_PUBLIC" and not _ip_public_ok(orig):
                continue
            if label == "IPV6_PRIVATE" and not _ipv6_private_ok(orig):
                continue
            if label == "USCC" and not _uscc_ok(orig):
                continue
            if label == "CONNSTR" and not _connstr_ok(orig, m, text):
                # 记下被豁免的区间：CONNSTR 排在 EMAIL 之前，下面必须让 EMAIL 避开
                # 与它重叠的命中，否则「口令尾@host」会被当邮箱吃掉留下半明文。
                if len(exempt_conn) < _CONNSTR_EXEMPT_MAX:
                    exempt_conn.append((m.start(), m.end()))
                continue
            if label == "EMAIL" and _overlaps_exempt_conn(m.start(), m.end(), exempt_conn):
                continue
            _hit(orig, label)
            matched.append(orig)
        # 按唯一原文替换（dict.fromkeys 去重且保序）。曾直接 `for orig in matched`：
        # matched 记的是命中「次数」而非唯一原文，同一个手机号在长上下文里出现上万次
        # 就对全文做上万次 str.replace，而 str.replace 本就是全局替换、第二次起纯属
        # 无用功 → 整条管线退化成 O(命中次数 × 文本长度)。
        # 实测 256KB 请求体：命中 11037 次、唯一原文仅 4 个，替换环节 930ms;
        # 512KB 达 3696ms（去重后 2.9ms，输出逐字节一致）。mitmproxy addon 跑在
        # asyncio event loop 上同步执行，这几秒会冻结全部 upstream 端口的所有连接，
        # 包括进行中的 SSE 流 —— 表现为「打字机卡死 + 其他客户端超时」。
        # 同时跳过已有占位符片段（防污染：内置规则如 hex 匹配会劈开占位符）
        if matched:
            unique_orig = list(dict.fromkeys(matched))
            repl_map = {orig: fwd[orig] for orig in unique_orig}
            def _rule_sub(m):
                orig = m.group(group_idx)
                if orig in repl_map:
                    if group_idx == 0:
                        return repl_map[orig]
                    # group_idx > 0：只替换捕获组部分，保留匹配的其他文本
                    # （如 Bearer 规则匹配「Bearer sk-xxx」，只替换「sk-xxx」）
                    gs, ge = m.span(group_idx)
                    return m.group(0)[:gs - m.start()] + repl_map[orig] + m.group(0)[ge - m.start():]
                return m.group(0)
            curr_len = len(text)
            text, edits = _mask_excluding_placeholders_ed(text, rx, _rule_sub, group_idx=group_idx)
            _update_om(edits, curr_len)

    # ── AI 实体识别（NER）：人名 (NAME) / 机构 (ORG) / 详细地址 (ADDR) ──
    # 排在全部确定性规则之后：同一原文以规则/自定义词为准，语义模型只补规则覆盖不到
    # 的自由文本。模型在干净的 original 上抽取上下文，抽出的区间经 om.map_range
    # 翻译至伤疤文本坐标系，再由 _ner_entity_spans 按占位符切分（测试验证见
    # tests/test_shield.py 中的 OffsetMapTests 与 tests/test_regressions.py）。
    # om_broken 或 om 为 None 时跳过 NER，严禁将 original 坐标作为回退直接用于伤疤文本。
    if NER_ENABLED and not om_broken and om is not None:
        try:
            import ner_engine
            if not ner_engine.is_ner_available():
                _ner_warn_once("model_missing",
                               "NER 已开启但模型文件不可用（%s），本次未做实体识别"
                               % ner_engine.status().get("model_dir"))
            else:
                entities = ner_engine.extract_entities(original)
                translated_entities = []
                for ent in entities:
                    if not isinstance(ent, dict):
                        continue
                    try:
                        s_orig = int(ent["start"])
                        e_orig = int(ent["end"])
                    except (KeyError, TypeError, ValueError):
                        continue
                    lbl = str(ent.get("type") or "TERM")
                    if e_orig - s_orig < 2 or s_orig < 0 or e_orig > len(original):
                        continue
                    mapped_range = om.map_range(s_orig, e_orig)
                    if mapped_range is None:
                        continue
                    s2, e2 = mapped_range
                    if e2 - s2 < 2:
                        continue
                    translated_entities.append({"start": s2, "end": e2, "type": lbl})

                planned = []
                for s0, e0, lbl in _ner_entity_spans(text, translated_entities):
                    raw_frag = text[s0:e0]
                    frag = raw_frag.strip()
                    if len(frag) < 2:
                        continue
                    # 实体区间两端可能带空白，收窄到 strip 后的边界，
                    # 免得把空格/换行一起换成占位符（还原后会丢排版）。
                    lead = len(raw_frag) - len(raw_frag.lstrip())
                    # 记账口径说明（易错，必须保留）：_hit() 必须传伤疤坐标系的残片 frag，
                    # 绝不能传原文实体。因为 restore() 会把占位符换回 fwd[TOKEN]，
                    # 出网文本在该位置只剩残片，注册成完整原文会导致还原时把占位符覆盖的部分重复吐出。
                    _hit(frag, lbl)
                    token = fwd.get(frag)
                    if token:
                        planned.append((s0 + lead, s0 + lead + len(frag), token))
                if planned:
                    # 起点相同时贪心优先覆盖更长的区间，防止短区间覆盖导致长区间残片明文泄漏
                    planned.sort(key=lambda x: (x[0], -x[1]))
                    text = _mask_by_spans(text, planned)
        except Exception as e:
            _ner_warn_once("runtime", "NER 识别降级，本次未做实体识别: %s: %s" % (type(e).__name__, e))

    # last_hits / new_orig 累积而非覆盖：mask() 被 _mask_tree 对每个字符串叶子
    # 各调一次，覆盖会让 count 只反映最后一个叶子的命中（曾导致 MASK 行
    # 「脱敏列 0、明细 2 项」自相矛盾）。
    # new_orig 累积全部新增；上报时与 last_hits 交集算「本次命中且新增」。
    s.setdefault("last_hits", set()).update(hit_orig)
    s.setdefault("new_orig", set()).update(new_orig)
    return text


# _PLACEHOLDER_RX / _PARTIAL_RX 已在 mask() 前定义（防占位符污染辅助函数依赖）

def _touch_recent(token, orig, now=None):
    """命中即续期（滑动过期）。

    原来只有 mask 侧（_recall_token）会刷新时间戳，restore 侧只读不刷。
    后果：一个原文在对话开头出现一次之后就再没被 mask 过，但模型每轮都在复述
    它的占位符——这条映射明明一直在用，时间戳却停在第一次，24h 一到照样被清，
    之后整段历史的这个占位符全部还原不了。缓存该有的是「活跃就续命」，
    绝对时间只是兜底上界。

    两个方向都要刷：_prune_recent 是按 _RECENT_FWD 的时间戳扫的，
    只刷 REV 的话照样会被连带删掉。
    """
    now = now or time.time()
    rev = _RECENT_REV.get(token)
    if rev is not None:
        rev[2] = now
    fwd = _RECENT_FWD.get(orig)
    if fwd is not None and fwd[0] == token:
        fwd[2] = now


def _lookup(token, sid):
    """占位符 → 原文。先查本会话，再查跨请求复用表，最后做套娃解包。

    **不做模糊匹配、不猜、不推算。** 0.1.12 曾加过一段「幻觉 IP 智能自愈」：
    模型把 {{IPPRIVATE_83fc6a}} 自行改写成 {{IPPRIVATE_83fc00}} 时，
    拿前 3~4 位 hex 去匹配已知 IP，再把末两位 hex 当十进制主机位算出一个地址。
    该逻辑 0.1.13 已整体删除，原因是它的前提不成立：

    - hex6 来自 `_new_token` 的 `secrets.token_hex(3)`（该函数 docstring 原话：
      "never derive IDs from secrets"）。`83fc` 不是子网前缀、`6a` 不是主机位，
      它们与 192.168.119.5 之间没有任何数学关系。对随机数做算术得到的 IP，
      **是用户从未输入过的数据**。
    - 实测：6 个从未登记的幻觉占位符里 5 个被编出地址；前缀只比 3 位 hex
      （4096 桶），已知 200 个 IP 时随机幻觉 token 的编造率 4.53%，
      且多网段共存时落到哪个网段取决于 dict 遍历顺序。
    - 编造走的是 `s["restored"] += 1` 这条正常路径，日志里分辨不出真假。

    模型自造的占位符从来没被登记过，表里没有它、也没有能推出它的东西——
    还原它在信息论上就不可能。正确行为是**原样保留 + 计入 unresolved**，
    让用户看得见「模型这里编了个东西」。要根治的是模型为什么想改写
    （它需要表达「该网段的 .0」却只有不透明 token），那属于脱敏格式的设计，
    不是还原侧能补的。
    """
    s = sessions.get(sid)
    hit = None
    if s:
        hit = s["rev"].get(token)
        if hit is not None:
            _touch_recent(token, hit)

    if hit is None:
        recent = _RECENT_REV.get(token)
        if recent:
            if _is_custom_word_orig(recent[0]) or _is_custom_word_token(token) or time.time() - recent[2] <= _recent_ttl():
                _touch_recent(token, recent[0])
                hit = recent[0]

    # 兜底：如果 _RECENT_REV 没命中（例如外部重置了复用表），直接查永久映射表
    if hit is None:
        c_rec = _CUSTOM_WORD_REV.get(token)
        if c_rec:
            hit = c_rec[0]
            _touch_recent(token, hit)

    # 防占位符套娃解包（如 A 被误脱敏为 B，递归解包直到真实明文）
    depth = 0
    while hit is not None and isinstance(hit, str) and _PLACEHOLDER_RX.match(hit) and depth < 5:
        depth += 1
        inner = None
        if s:
            inner = s["rev"].get(hit)
        if inner is None:
            rec = _RECENT_REV.get(hit)
            # 内层同样校验 TTL：套娃解包走的是「外层校验过、内层没校验」的缝隙，
            # 会用一条早已过期的映射完成还原，突破 24h 原文保留窗口契约
            if rec:
                if _is_custom_word_orig(rec[0]) or _is_custom_word_token(hit) or time.time() - rec[2] <= _recent_ttl():
                    inner = rec[0]
            if inner is None:
                c_rec = _CUSTOM_WORD_REV.get(hit)
                if c_rec:
                    inner = c_rec[0]
        if inner is not None and inner != hit:
            hit = inner
        else:
            break

    # 如果最终还是占位符自身，说明没有真实明文
    if hit is not None and isinstance(hit, str) and _PLACEHOLDER_RX.match(hit):
        return None

    return hit


def restore(text, sid, channel="", escape=False, final=False):
    """把占位符还原成原文。

    channel: 流式通道标识。半截占位符只在本通道缓冲，正文 delta 与 tool 参数 delta
             互不串扰（共用一个缓冲会把上一个字段的尾巴吐进下一个字段）。
    escape:  目标位置是 JSON 字符串内部（tool_calls.arguments / partial_json），
             原文里的引号、换行必须按 JSON 转义，否则客户端解析工具参数直接报错。
    final:   True = 不再等后续 chunk，缓冲区一次性吐出。
    """
    s = sessions.get(sid)
    if not s or not isinstance(text, str):
        return text
    pend = s["pending"]
    if not isinstance(pend, dict):  # 兼容旧结构
        pend = s["pending"] = {}
    buf = pend.get(channel, "") + text
    if final:
        pend.pop(channel, None)
        confirmed = buf
    else:
        m = _PARTIAL_RX.search(buf)
        if m and m.end() == len(buf) and len(m.group()) <= _PARTIAL_MAX:
            confirmed = buf[: m.start()]
            pend[channel] = m.group()
        else:
            confirmed = buf
            pend.pop(channel, None)
    if not confirmed:
        return ""

    def _sub(m):
        whole = m.group(0)
        lab_raw = m.group(1)
        suffix = m.group(2)
        canon = "{{%s_%s}}" % (lab_raw.upper(), suffix.lower())
        orig = _lookup(canon, sid)
        via_suffix = False
        real_token = canon if orig is not None else None
        if orig is None:
            # 标签被模型改写（补回下划线 / 全小写 / 变异）时按后缀反查。
            # 这里是双花括号形态，由 _BRACED_PLACEHOLDER_RX 保证带花括号，可以安全走后缀索引。
            real = _suffix_real_token(canon)
            if real is not None:
                orig = _lookup(real, sid)
                if orig is not None:
                    real_token = real
                    via_suffix = True
            if orig is None:
                orig = _lookup_by_suffix(canon, sid)
                if orig is not None:
                    via_suffix = True
                    real_token = canon
        if orig is None:
            # 占位符查不到原文（复用表被淘汰/会话被扫掉/客户端历史带入的孤儿）：
            # 只有当它是标准的紧凑形态时才计数 unresolved，原样返回（不能猜）
            if _PLACEHOLDER_RX.match(whole):
                s["unresolved"] = s.get("unresolved", 0) + 1
            return whole
        s["restored"] = s.get("restored", 0) + 1
        s["restored_tokens"].add(real_token or canon)
        s.setdefault("restored_origs", set()).add(orig)
        if via_suffix or whole != canon:
            # 靠空格容错或改写容错救回来的，计入 degraded
            s["degraded"] = s.get("degraded", 0) + 1
        return json.dumps(orig, ensure_ascii=False)[1:-1] if escape else orig

    out = _BRACED_PLACEHOLDER_RX.sub(_sub, confirmed)

    # 第二遍：转义形态 `\{\{X\}\}` / `\\{\\{X\\}\\}`，含内部可选空白。
    #
    # 必须跑在宽松遍之前：宽松正则不带花括号匹配，在转义形态上只吃得到中间
    # 一段，替换完会留下 `\{\` 与 `\}\}` 残渣 —— IP 出来了但命令仍然是坏的，
    # 用户会误判成「还原成功」。这一遍把整个转义块（连同反斜杠与内部空白）一起替换掉。
    # 同样只认查得到原文的 token，查不到原样放回，绝不猜。
    if "_" in out:
        def _esc_sub(m):
            whole = m.group(0)
            canon = "{{%s_%s}}" % (m.group(1).upper(), m.group(2).lower())
            orig = _lookup(canon, sid)
            real = canon if orig is not None else None
            if orig is None:
                real = _suffix_real_token(canon)
                if real is not None:
                    orig = _lookup(real, sid)
            if orig is None:
                return whole
            s["restored"] = s.get("restored", 0) + 1
            s["degraded"] = s.get("degraded", 0) + 1
            s.setdefault("restored_origs", set()).add(orig)
            # 记账用真实 token：RESTORE 明细按签发时的 token 比对 restored 标记，
            # 存模型改写后的形态会查不到，该项被误标成「未还原」（假阴性）。
            s["restored_tokens"].add(real)
            return json.dumps(orig, ensure_ascii=False)[1:-1] if escape else orig
        out = _ESCAPED_PLACEHOLDER_RX.sub(_esc_sub, out)

    # 第三遍：捞回被模型剥了花括号 / 只剩单花括号的占位符。
    # 只在前面两遍之后跑，且只认「查得到原文」的 token——查不到就原样放回，绝不猜。
    # **这一遍不走后缀索引**：裸 token 可能只是被 chunk 切开的残片，按后缀命中
    # 就会把残片替换成明文（见 _RECENT_SUFFIX 注释）。
    # degraded 计数进 RESTORE 事件（`degraded=` 参数，见 _restore_emit），
    # 让用户看得见「这次是靠兜底修回来的」。这句注释曾在此、而 _emit 里根本没这个
    # 参数——计数只加在会话 dict 里，从没发出去过，于是这条信息永远查不到。
    # 实测生产库 8805 条 RESTORE 里该字段一条都不存在，正是因此。0.1.14 补上。
    if "_" in out:
        def _loose_sub(m):
            whole = m.group(0)
            if whole.startswith("{{") and whole.endswith("}}"):
                return whole  # 双花括号形态第一遍已处理
            tok_body = (m.group(1) or m.group(2) or "").strip()
            canon = "{{" + tok_body + "}}"
            orig = _lookup(canon, sid)
            real = canon if orig is not None else None
            if orig is None and whole.startswith("{"):
                real = _suffix_real_token(canon)
                if real is not None:
                    orig = _lookup(real, sid)
            if orig is None:
                return whole
            s["restored"] = s.get("restored", 0) + 1
            s["degraded"] = s.get("degraded", 0) + 1
            s.setdefault("restored_origs", set()).add(orig)
            if real is not None:
                s["restored_tokens"].add(real)
            return json.dumps(orig, ensure_ascii=False)[1:-1] if escape else orig
        out = _LOOSE_PLACEHOLDER_RX.sub(_loose_sub, out)
    return out


def restore_final(text, sid, escape=False):
    return restore(text, sid, escape=escape, final=True)


# 这些字段的字符串本身是 JSON 文本（tool 参数），还原时原文需转义
_JSON_STR_KEYS = {"arguments", "partial_json"}


_RESTORE_MAX_DEPTH = 24


def _count_unresolved(sid, n=1):
    """会话级 unresolved 计数（与 restore() 维护同一字段，只用于诊断展示）。"""
    s = sessions.get(sid)
    if isinstance(s, dict):
        try:
            s["unresolved"] = int(s.get("unresolved") or 0) + n
        except Exception:
            pass


def _restore_tree(obj, sid, key=None, depth=0):
    """递归还原 JSON 里所有字符串叶子。

    响应结构五花八门（choices[].message、Anthropic content[].tool_use.input、
    Responses output[]…），逐个格式硬编码必然漏。占位符只可能出现在我们脱敏过的
    位置，整树扫一遍是安全的，且天然覆盖 tool 调用参数。
    """
    if depth > _RESTORE_MAX_DEPTH:
        # 超深不再静默：请求侧同深度是 fail-closed（_mask_tree 抛 json_depth_exceeded），
        # 响应侧此前直接原样返回——占位符就此永久留在回复里，而会话计数毫无变化，
        # 排障时分不清「这里没还原」和「本来就没有占位符」。
        _count_unresolved(sid, 1)
        return obj
    if isinstance(obj, str):
        return restore_final(obj, sid, escape=key in _JSON_STR_KEYS)
    if isinstance(obj, list):
        return [_restore_tree(v, sid, key, depth + 1) for v in obj]
    if isinstance(obj, dict):
        return {k: _restore_tree(v, sid, k, depth + 1) for k, v in obj.items()}
    return obj


# ===== 递归脱敏的跳过策略（完整路径判定，v1.5.19 起） =====
# 审计实测：按字段名整体跳过 name/url/id/data/type/role，会让 tool 参数里的
# 业务字段（input_name 的姓名、input_url 里的手机号、input.type 里的号码）原文直出。
# 规则：
# - 业务区（tool_use.input / function.arguments 等参数容器）内一律照常扫描，
#   不应用任何字段名豁免——业务字段的敏感值必须脱敏；
# - 业务区外的跳过按「完整路径 + 协议位置」判定，禁止裸字段名豁免。
# model 全局跳过（模型名不是 PII 且扫描无害）；object/finish_reason 等响应侧枚举同理。
# ⚠️ 这个集合**只对字符串叶子生效**（判定点在 _mask_tree 的 str 分支）。
# 键的值若是对象/数组，写在这里也拦不住——递归会照常进到子树里。
# 2026-09 实测 `cache_control` 就是这种情况：它一直被列在本集合里，但
# `{"type": "ephemeral"}` 里的 "ephemeral" 仍会被自定义词表命中，写成
# `{"type": "{{TERM_xxxxxx}}"}`，Anthropic 侧缓存指令当场失效。
# **dict 值的键请用 _MASK_SKIP_SUBTREE_KEYS。**
_MASK_SKIP_SCALAR_KEYS = {
    "model", "object", "finish_reason", "stop_reason",
    "citations", "detail", "encoding_format", "media_type",
}
# 值恒为「协议元数据对象」的键：整棵子树跳过（判定点在 dict 分支开头）。
# 收录门槛很窄——只收结构固定、绝无业务载荷的键，因为整棵跳过 = 放弃该子树里
# 全部字符串的扫描，是一条实打实的漏检路径：
#   cache_control 形如 {"type": "ephemeral", "ttl": "1h"}，改写它只会让上游
#   判缓存指令非法，保护不了任何东西。
# 故意**不收** response_format 与 format（两者同为 dict 值，同样"死条目"）：
#   - OpenAI 的 response_format.json_schema.schema 可以带 enum 示例值；
#   - Ollama 的 format 可以是一整份 JSON Schema，其 enum 同样可能承载真实业务取值。
# 整棵跳过它们收益为零（里面本就没有 PII 以外的数据），风险却是新增漏检面。
# 见 tests/test_regressions.py::MaskPathAwarenessTests 的反向锁用例。
_MASK_SKIP_SUBTREE_KEYS = {"cache_control"}
# role/type 是判别字段，但只在其协议容器内跳过；出现在业务自定义对象里
# （如 {"type": "13812345678"}）必须扫描——审计实测 input.type 原文上行即此类。
_MASK_ROLE_TYPE_PARENTS = {
    "message", "messages", "content", "contents", "parts", "block", "blocks",
    "tools", "tool", "tool_calls", "function", "response_format",
    "candidates", "choices", "output",
}
# id 只在协议容器位置跳过（消息/块级关联 ID，客户端靠它关联流内对象）；
# 业务对象里的 customer.id 等照常扫描（审计验收点）。
_MASK_PROTOCOL_ID_PARENTS = {
    "message", "messages", "content", "contents", "parts", "block", "blocks",
    "tool_calls", "tool_use", "response", "output", "data", "object",
    "candidates", "choices", "function_call",
}
# 只在这类父 key 下才豁免的字段（工具名/媒体容器）。
# 覆盖 OpenAI tools[].function / 旧式 functions[] / function_call（含响应侧）、
# Anthropic tool_use、Gemini functionCall，以及 image_url/inline_data 等媒体容器。
_MASK_PROTOCOL_PARENTS = {
    "function", "functions", "function_call", "functionCall", "tool_use", "tools", "tool",
    "image_url", "inline_data", "thumbnail", "input_image", "source", "file",
}
_MASK_SKIP_KEYS = {"id", "tool_call_id", "tool_use_id", "name", "url", "data", "b64_json"}
# 工具调用关联 ID：上游生成的不透明句柄，客户端靠它把工具结果连回上一轮函数调用。
# 这组**不分业务区一律豁免**（判定点在 _mask_tree 的 in_business 之前），
# 因为脱敏它必然断链且保护不了任何东西。call_id 是 OpenAI Responses API 的形式，
# tool_call_id 是 Chat Completions 的，tool_use_id 是 Anthropic 的。
_MASK_CORRELATION_ID_KEYS = {"tool_call_id", "tool_use_id", "call_id"}
# 业务区容器 key：进入后任何字段都照常扫描
_MASK_BUSINESS_KEYS = {"input", "arguments", "parameters", "partial_json", "documents"}
_MASK_MAX_DEPTH = 24

# 数值型协议字段：这些键的**数值**是协议参数（采样参数、用量计数、序号），
# 不是业务数据。{"seed": 1234567890123456} 这种随机大整数完全可能被 Luhn 校验
# 误判成卡号 —— 一旦改写，请求当场被上游拒绝。所以数值分支对它们一律豁免。
# ⚠️ 只对**数值**豁免，字符串形态照常扫描（`{"seed": "13800138000"}` 仍会命中）。
_MASK_SKIP_NUMERIC_KEYS = {
    "max_tokens", "max_completion_tokens", "max_tokens_to_sample", "budget_tokens",
    "temperature", "top_p", "top_k", "n", "seed", "index", "created", "logprobs",
    "top_logprobs", "presence_penalty", "frequency_penalty", "best_of", "timeout",
    "prompt_tokens", "completion_tokens", "total_tokens", "input_tokens", "output_tokens",
    "cache_creation_input_tokens", "cache_read_input_tokens", "reasoning_tokens",
    "status_code", "http_status", "retry", "attempt", "weight", "priority",
}

# 对象**键名**的白名单：集合内的键永不脱敏，集合外一律当「数据键」扫描。
#
# 为什么需要这个集合：旧实现「键名一律不脱敏」让 `{"13800138000": "safe"}` 这种
# PII-as-key 形态整条明文上行（审计 B2 实测）。但直接放开又会踩另一个坑 ——
# 用户自定义短词（比如加个 "con"）会命中 `content`，把协议骨架打坏，
# 代价是**每个请求都坏**，比漏一个罕见载荷形状严重得多。
#
# 所以判据从「要不要扫」翻转成「哪些键是结构键」：这里穷举协议/角色/JSON Schema
# 词汇，命中即豁免；剩下的键才是数据键。新增协议字段时**必须同步加到这里**，
# 否则该字段名会被当数据脱敏（症状：上游报参数非法）。
_MASK_PROTECTED_KEY_NAMES = frozenset(
    set(_MASK_SKIP_SCALAR_KEYS)
    | set(_MASK_SKIP_SUBTREE_KEYS)
    | set(_MASK_SKIP_KEYS)
    | set(_MASK_CORRELATION_ID_KEYS)
    | set(_MASK_ROLE_TYPE_PARENTS)
    | set(_MASK_PROTOCOL_PARENTS)
    | set(_MASK_PROTOCOL_ID_PARENTS)
    | set(_MASK_BUSINESS_KEYS)
    | {
        # 对话协议骨架
        "role", "type", "content", "contents", "parts", "messages", "message",
        "system", "user", "assistant", "tool", "tools", "function", "functions",
        "prompt", "input", "output", "text", "delta", "choices", "candidates",
        "usage", "error", "code", "status", "version", "headers", "request",
        "response", "metadata", "stream", "stop", "stop_sequences", "logit_bias",
        "response_format", "stream_options", "parallel_tool_calls", "tool_choice",
        "system_instruction", "generationConfig", "safetySettings", "toolConfig",
        "functionDeclarations", "functionCall", "inline_data", "image_url", "source",
        "anthropic_version", "thinking", "signature",
        # JSON Schema 词汇（response_format / format 里可能是整份 schema）
        "schema", "json_schema", "format", "definitions", "$defs", "$ref", "$schema",
        "properties", "required", "items", "enum", "const", "description", "title",
        "additionalProperties", "anyOf", "oneOf", "allOf", "not", "if", "then", "else",
        "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
        "minLength", "maxLength", "minItems", "maxItems", "pattern", "default",
        "examples", "nullable", "strict", "name", "strict_mode",
        # 缓存 / 计费 / 诊断指令
        "cache_control", "ttl", "ephemeral",
        # 对话协议顶级控制参数（涵盖各大模型标准字段，对齐 PROTOCOL_TOP_KEYS）
        # ⚠️ 这一组是**协议骨架**，被改名等于上游 400。别漏 `n`（OpenAI 的
        # `n` = 生成几条候选，单字母键最容易在补白名单时被漏掉）。
        "temperature", "top_p", "top_k", "n", "max_tokens", "max_completion_tokens",
        "max_output_tokens", "presence_penalty", "frequency_penalty", "seed",
        "logprobs", "top_logprobs", "modalities", "audio", "prediction", "store",
        "service_tier", "reasoning", "reasoning_effort", "thinking_budget",
        "betas", "anthropic_beta", "context_management", "mcp_servers", "container",
        "generation_config", "safety_settings", "candidate_count", "systemInstruction",
        "session_id", "request_id", "keep_alive", "options", "api_key", "x_api_key",
        "authorization", "instructions", "tool_config",
    }
)
# 顶层非对象 JSON 的合成根键：只在 request() 内部存在，发往上游前一定会拆掉。
# 取一个绝不会与真实字段重名、且不落在任何跳过名单里的名字，保证叶子照常被扫描。
_ROOT_WRAP_KEY = "__shield_root__"


# 首个差异字节的扫描上限。超过就不算（记 -1）。
# 实测（二分 + 切片比较，差异位置越靠后越贵）：1MB 14.5ms、8MB 173ms、32MB 约 700ms。
# 这个值只用于「前缀有没有被改动」的诊断，而它在回写分支里**每次都调**
# （与 splice 成不成无关），不值得为它拖慢热路径。
# ⚠️ 别跟着 `_SPLICE_MAX`（8MB）一起放宽（见那里的注释）。
_FIRST_DIFF_MAX = 1 << 20


def _first_diff_byte(a, b):
    """返回 a、b 首个不同字节的下标；一方是另一方前缀时返回较短者的长度。

    只用于诊断（MASK 事件的 first_diff_byte），**不参与任何脱敏决策**。
    用途：判断「命中敏感词时，客户端原始 body 的排版是否被我们的重序列化改掉了」——
    差异位若正好落在第一个被脱敏的值上，说明客户端本来就在发紧凑体，
    当前的回写方式没有额外损失；差异位若远小于它（例如 byte 9 的
    `{"model": ` 空格），说明还有整段前缀被凭空改动，值得考虑字节级替换。

    实现用二分 + 切片相等比较：每次比较是 C 级 memcmp，整体 O(log n) 次，
    避免 Python 逐字节循环在 MB 级请求体上跑到几百毫秒。切片相等性对前缀长度
    单调（长度 m 的公共前缀 ⇒ 所有更短的也相等），所以二分成立。
    """
    if len(a) > _FIRST_DIFF_MAX or len(b) > _FIRST_DIFF_MAX:
        return -1
    n = min(len(a), len(b))
    if n == 0:
        return -1 if len(a) == len(b) else 0
    if a[:n] == b[:n]:
        return -1 if len(a) == len(b) else n
    lo, hi = 0, n - 1
    while lo < hi:
        mid = (lo + hi) // 2
        if a[:mid + 1] == b[:mid + 1]:
            lo = mid + 1
        else:
            hi = mid
    return lo


# 字节级替换的体积与条目上限。超过就退回整棵重序列化。
#
# `_SPLICE_MAX` 取 8MB。早先取 1MB 的注释理由是「省下的前缀对齐收益抵不过 CPU
# 开销」，**实测不成立**——完整路径（`_splice_mask` + 调用方的 `json.loads` 等价校验）
# 对退路 `json.dumps` 的比值：1MB 3.2/2.4ms（1.34x）、8MB 28.0/23.9ms（1.17x），
# 最坏只多 4ms（敏感值 1→64 个耗时只差 2 倍，不是分支数的线性放大）。
# 而 1MB 恰好把**长会话**挡在了外面——那恰恰是上游 Prompt Cache 收益最大的场景，
# 上下文越长，前缀 miss 一次越贵。
#
# ⚠️ 别把它和 `_FIRST_DIFF_MAX`（1MB）联动放宽：后者是每次回写都要算的纯诊断值，
# 耗时随差异位置后移暴涨（1MB/最末 14.5ms、8MB 173ms），跟着放宽等于给热路径加
# 100ms+。后果：>1MB 的请求 splice 生效但 `first_diff_byte` 记 -1，仪表盘
# 「平均首个差异字节」样本数为 0 —— **已知口径，不是 bug**，别重复排查。
#
# `_SPLICE_MAX_FORMS = 128` 是**另一条独立的退回线**：本次请求里被脱敏的**唯一原文**
# 数上限（每个原文按「原字符 / \uXXXX」两种合法 JSON 写法各建一条交替分支，
# 所以 128 个原文 ≈ 256 个分支）。超了 `_splice_mask` 直接返回 None，同样退回整棵
# 重序列化 → 前缀又被改，首个差异位回到 body 开头附近。
#   · 为什么是 128 而不是 64：2026-09-13 在 8MB body 上复测了上限档位——splice 生效
#     的耗时与退路的 `json.dumps` **同价**（32 分支 21ms / 128 分支 23ms / 256 分支
#     27ms vs dumps 22ms），退回并没有省时间，只是白白丢掉前缀保真；而分支数在
#     64→256 区间内几乎不放大耗时（主成本在大 body 扫描本身）。取 128 是让日常长会
#     话（单请求几十个不同敏感值）不再踩线，同时保留体积上限做硬护栏。继续放宽的
#     代价仍是同价的，若未来感知到慢再回来复测档位——只要分支数仍在个位数毫秒级。
#   · 唯一副作用也附带测量过：splice 生效与否不影响脱敏/还原正确性（两端都是同一
#     棵已脱敏树，还原只看占位符→rev 表），只影响发往上游字节的前缀保真。
#   · 诊断方式：这类请求 `body_rewritten=true` 但 `first_diff_byte` **明显早于敏感值
#     在 body 里的真实位置**（客户端用带空格排版时约在 byte 9），而 splice 生效时
#     差异位正好落在敏感值上 —— 两者对照一眼可辨。
_SPLICE_MAX = 8 << 20
_SPLICE_MAX_FORMS = 128


def _splice_mask(raw, masked_root, pairs):
    """把 raw 里被脱敏的原文**就地**换成占位符，保住客户端 body 的原始排版。

    为什么值得多这一条路径：命中敏感词时旧实现用 `json.dumps` 整棵重序列化，
    客户端 body 的排版（冒号后空格、缩进、`1e-05` 这类数字写法）被一并抹掉，
    与客户端原始字节的首个差异位就从「真正的敏感值」前移到 body 开头附近
    （实测一条带空格 + `\\u` 转义的请求：敏感值在 byte 74，差异位却在 byte 9）。
    上游按前缀做的 Prompt Cache 从差异位起整段 miss，中间那 65 个字节被白白改掉。

    做法：对每个被脱敏的原文，按「原字符」与「\\uXXXX」两种合法 JSON 写法各建一条
    替换项，在原始字节上一次性替换 —— 客户端用哪种转义风格，占位符就用哪种写回去。
    不做结构解析，所以不动键名、不动数字字面量、不改排版。

    ⚠️ **正确性不由这个函数保证**：调用方必须校验
    `json.loads(结果) == masked_root`，不过就整条退回 `json.dumps`。
    所以这里可以粗暴 —— 多替换了（命中键名、命中 `_mask_tree` 有意跳过的位置、
    把历史里已有的占位符切碎）都会被等价校验拦下，退回**同一棵已经脱敏的树**。
    因此这条路径在任何情况下都不会放行原文，最差只是回到改动前的行为。

    pairs: {原文: 占位符}。返回替换后的字节；一个都没替换就返回 None。
    """
    if not pairs or not raw or len(raw) > _SPLICE_MAX:
        return None
    table = {}
    for orig, tok in pairs.items():
        if not orig or not tok or orig == tok:
            continue
        for ascii_esc in (False, True):
            lit = json.dumps(orig, ensure_ascii=ascii_esc)[1:-1]
            repl = json.dumps(tok, ensure_ascii=ascii_esc)[1:-1]
            if lit != repl:
                table[lit.encode("utf-8")] = repl.encode("utf-8")
    if not table or len(table) > _SPLICE_MAX_FORMS:
        return None
    # 长 form 优先：正则交替是「首个匹配胜出」，短原文若是长原文的子串，
    # 排在前面就会把长原文切碎。
    forms = sorted(table, key=len, reverse=True)
    pat = re.compile(b"|".join(re.escape(f) for f in forms))
    new, hits = pat.subn(lambda m: table[m.group(0)], raw)
    return new if hits else None


def _mask_hit(obj, sid, flag=None):
    """调 `mask()` 并记录「这个请求体真的被改写过」。

    flag 是调用方传进来的单元素 list（None = 调用方不关心）。用途见
    `_mask_tree` 的调用方：一个敏感词都没命中时**完全不回写**
    `flow.request.content`，让上游收到的字节与客户端发出的逐字节一致。

    为什么非要有这个标记：`json.dumps` 的默认分隔符是 `(", ", ": ")`，
    重序列化会在每个逗号/冒号后插空格；`ensure_ascii` 的取值还会决定非 ASCII
    是写成 `\\u5f20` 还是「张」。哪怕一个敏感词都没命中，这两点也足以让上游
    收到的字节与客户端发出的不同 —— 上游按前缀做 Prompt Cache，前缀一变就
    整段 miss（实测紧凑体 113 字节被改写成 123 字节）。
    """
    out = mask(obj, sid)
    if flag is not None and out != obj:
        flag[0] = True
    return out


def _leaf_exempt(key, parent, in_business):
    """叶子（字符串 / 数值）是否落在「协议位置」从而豁免扫描。

    抽成独立函数是因为 str 与数值两个分支必须用**同一套**判据：数值型漏检
    （审计 B2）的根因之一就是数值分支压根没有判据、直接 `return obj`。

    判据细节（按优先级）：
    - 工具调用关联 ID：**不分业务区，一律豁免**。它是上游生成的不透明句柄
      （call_abc123），客户端要拿它把工具结果回连到上一轮函数调用。脱敏它必然断链，
      而且保护不了任何东西——里面没有用户原文，有也是上游必须逐字匹配的那份。
      所以这条判定必须在 in_business 之前。
      提前的原因（2026-08-17 外部审计）：OpenAI Responses API 把协议信封放进
      input[] 里 —— {"input":[{"type":"function_call_output","call_id":...}]}。
      而 input 是业务区容器，`if not in_business` 那一大块整个不进，
      于是 call_id 被当普通文本脱敏：call_ACME_9x → call_{{CUSTOMER_ed24da}}_9x。
      Chat Completions 的 tool_call_id 在 messages[] 里（非业务区）所以一直没事，
      两边行为不一致纯属遗漏，不是设计。
    - 业务区内一律不豁免（见 `_mask_tree` 的说明）。
    - 业务区外按「完整路径 + 协议位置」判定，禁止裸字段名豁免。
      只列关联 ID，不含 name/url/id 等——那些在业务对象里确实可能载有原文
      （customer.id、正文里的 url），维持按位置判定（见 AGENTS 约束 12）。
    """
    if key in _MASK_CORRELATION_ID_KEYS:
        return True
    if in_business:
        return False
    if key in _MASK_SKIP_SCALAR_KEYS:
        return True
    if key in ("role", "type") and (parent is None or parent in _MASK_ROLE_TYPE_PARENTS):
        return True
    if key in _MASK_SKIP_KEYS:
        # 协议位置判定（业务区内不豁免）：
        # - name：仅工具定义/调用位置的工具名（tools[].function.name / tool_use.name）
        # - url/data/b64_json：仅媒体容器里的图片 URL/base64（改了就破图）
        # - id：仅协议容器（messages/content/tool_calls/response/output 等）的关联 ID
        if key == "name" and parent not in _MASK_PROTOCOL_PARENTS:
            return False
        if key in ("url", "data", "b64_json", "image_url") and parent not in _MASK_PROTOCOL_PARENTS:
            return False
        if key == "id" and parent not in _MASK_PROTOCOL_ID_PARENTS:
            return False
        return True
    return False


def _mask_tree(obj, sid, key=None, parent=None, path=(), depth=0, flag=None):
    """递归脱敏 JSON 里的字符串叶子（完整路径判定 + 业务区强制扫描）。

    只处理 message.content 会整片漏掉多轮历史里的
    tool_calls[].function.arguments、Anthropic tool_use.input、tool_result.content —
    这些位置常年携带上一轮的真实值，是最容易被绕过的泄漏面。
    JSON 深度超过上限不再静默原文放行：抛异常走 fail-closed 阻断（fail-closed 关闭时
    记 ERR 跳过），杜绝"深到扫不到就直出"的泄漏路径。

    flag：可选单元素 list，任一叶子真的被替换过就置 True（见 `_mask_hit`）。
    调用方靠它决定「要不要回写请求体」——没命中就一个字都不改，保住上游前缀缓存。
    """
    if depth > _MASK_MAX_DEPTH:
        raise ValueError("json_depth_exceeded: 请求嵌套超过脱敏递归上限，拒绝透传")
    in_business = any(k in _MASK_BUSINESS_KEYS for k in path)
    if isinstance(obj, str):
        # 业务区（tool_use.input / function.arguments 等参数容器）内一律扫描：
        # 不应用任何全局字段名豁免——input 里的 type/role/model/id 都可能是业务数据
        # （审计实测：input.type 放手机号曾原文上行）。只有业务区外的协议位置才跳过。
        # 判据抽到 `_leaf_exempt`：数值分支必须用同一套，否则两边行为会漂。
        if _leaf_exempt(key, parent, in_business):
            return obj
        return _mask_hit(obj, sid, flag)
    # bool 是 int 的子类，必须先判掉：否则 True/False 会被 str() 成 "True"/"False"
    # 送去过规则（虽然默认词表不会命中，但自定义词表里加个 "True" 就会）。
    if isinstance(obj, bool) or obj is None:
        return obj
    if isinstance(obj, (int, float)):
        # 数值型标量（审计 B2 阻断项）。规则全是文本正则，而旧实现到这里直接
        # `return obj` —— 于是 {"phone": 13800138000} 这种形态**既不命中也不抛异常**，
        # changed 保持 False → 零改写分支把客户端原始字节原样放行，明文出网；
        # 而 fail-closed 只兜异常，兜不住「静默判定为无需改写」。
        # 修法：取字符串形态过一遍规则，命中才把整个值换成占位符（类型由 number
        # 变 string，上游读到的就是占位符，与字符串形态的脱敏结果一致）。
        if key in _MASK_SKIP_NUMERIC_KEYS or _leaf_exempt(key, parent, in_business):
            return obj
        s = repr(obj) if isinstance(obj, float) else str(obj)
        out = mask(s, sid)
        if out != s:
            if flag is not None:
                flag[0] = True
            return out
        return obj
    if isinstance(obj, list):
        return [_mask_tree(v, sid, key, parent, path, depth + 1, flag) for v in obj]
    if isinstance(obj, dict):
        # 协议元数据对象整棵跳过。必须放在 dict 分支——str 分支的
        # _MASK_SKIP_SCALAR_KEYS 对对象值无效（见该集合上方的注释）。
        if not in_business and key in _MASK_SKIP_SUBTREE_KEYS:
            return obj
        # 键名脱敏（2026-09 起，审计 B2）。旧实现是「键名一律不脱敏」，理由是
        # 键名承载结构语义、自定义短词误命中会把协议骨架打坏。这个顾虑成立，
        # 但它同时让 {"13800138000": "safe"} 这种 PII-as-key 形态整条明文上行。
        #
        # 现在的判据翻转成**结构键白名单**：`_MASK_PROTECTED_KEY_NAMES` 内的键永不
        # 脱敏，集合外一律当数据键扫描。于是「用户加个 con 命中 content」这类误伤
        # 被白名单挡住，而手机号/身份证当键名时能被打上。
        # 注意 path 仍用**原键** k 推进：in_business 判定必须看客户端真实的键名，
        # 用脱敏后的占位符去判会让下游整棵子树丢失业务区语义。
        masked_obj = {}
        for k, v in obj.items():
            new_key = k
            if isinstance(k, str) and k not in _MASK_PROTECTED_KEY_NAMES:
                masked_key = mask(k, sid)
                if masked_key != k:
                    new_key = masked_key
                    if flag is not None:
                        flag[0] = True
            masked_obj[new_key] = _mask_tree(v, sid, k, key, path + (k,), depth + 1, flag)
        return masked_obj
    return obj


def _seed_known(text, sid):
    """把请求里出现的、属于复用表的历史占位符登记进本会话 rev。

    客户端历史里带上来的上一轮占位符，本轮响应若被模型复述，仍能正确还原。
    """
    s = sessions.get(sid)
    if not s or not text:
        return
    for token in set(_PLACEHOLDER_RX.findall(text)):
        if token in s["rev"]:
            continue
        recent = _RECENT_REV.get(token)
        if recent and time.time() - recent[2] <= _recent_ttl():
            s["rev"][token] = recent[0]
            _touch_recent(token, recent[0])


# ===================== 浏览器扩展桥接（Browser Bridge v1）专用入口 =====================
# 这两个 helper 是 panel 的 /api/ext/mask 端点复用的入口，**不参与代理链路**。
# 它们都必须由调用方（panel 侧）持 `_EXT_LOCK` 调用：本文件的历史前提是
# "mitmproxy event loop 单线程同步执行"，`sessions` / `_RECENT_*` 都是无锁全局态，
# panel 的 Flask 是 threaded，不加锁会让 `_prune_recent` 的 `list()` 快照构造期
# 撞上并发插入 → RuntimeError。

def _mask_event_items(sid, limit=30):
    """构造与代理路径**同构**的 MASK 事件明细（items），供 panel 的 ext 端点落库。

    字段结构与代理响应侧构造对齐（`tok/label/hash/length/preview` + 凭据类
    `cred/digest` 或非凭据 `original` + 短词 `short`），这样 `_warmup_recent_from_db`
    预热与前端明细弹窗对两条链路的行为一致（SPEC C11/T14）。

    **唯一少一个字段：`roles`**（代理侧由 `role_texts` 反查「命中在第几个角色块」，
    那个映射来自代理的请求解析过程，扩展链路拿不到）。前端对缺失的 `roles` 是
    「不渲染归因角标」，不报错——所以这里是**有意的缺省，不是漏写**，别照抄代理侧
    的构造列表去补（补不出来，只会拿到 `roles=None` 被静默跳过）。

    **假定会话已由调用方显式建立**（端点先 `_new_session`），不做缺会话兜底——
    端点显式建会话正是为了让 inflight 保护落在真会话上。
    凭据类标签恒只回 digest+preview（不落原文），与项目隐私红线一致。
    """
    s = sessions.get(sid) or {}
    fwd = s.get("fwd") or {}
    labels = s.get("labels") or {}
    last_hits = s.get("last_hits") or set()
    # 本次命中的排前面，让事件的 count 与明细对得上（同代理路径口径）
    ordered = [o for o in last_hits if o in fwd] + [o for o in fwd if o not in last_hits]
    items = []
    for orig in ordered[:limit]:
        tok = fwd.get(orig, "")
        if not tok:
            continue
        m = _PLACEHOLDER_PARTS_RX.match(tok)
        label = labels.get(orig, "")
        item = {
            "tok": tok,
            "label": label,
            "hash": m.group(2) if m else "",
            "length": len(orig),
            "preview": _preview(orig, label),
        }
        if label in CREDENTIAL_LABELS:
            item["cred"] = True
            item["digest"] = _cred_digest(orig)
        else:
            item["original"] = orig
        if len(orig) <= 2:
            item["short"] = True
        items.append(item)
    return items


_DUP_KEY_WARNED = [False]


def _load_json_pairs(text):
    """解析 JSON，并同时报告**是否存在重复键**。返回 (obj, has_dupes)。

    为什么要单独判重复键：`json.loads` 对重复键取「后者覆盖前者」，解析结果无法
    代表原文。于是 `{"a":"13800138000","a":"safe"}` 的树里只剩 "safe"，`_mask_tree`
    扫不到那个手机号 → changed 保持 False → 零改写分支把**原始字节**原样放行
    （审计 B2 实测）。命中其它字段时同样不能走 `_splice_mask`：丢掉的键不在替换表里，
    而等价校验又会因为「splice 结果解析回来仍等于脱敏树」而误判通过，明文照样出网。

    解析失败返回 (None, False) —— 由调用方走各自的「非 JSON 体」分支。
    """
    dupes = [False]

    def _pairs(pairs):
        d = dict(pairs)
        if not dupes[0] and len(d) != len(pairs):
            dupes[0] = True
        return d

    try:
        return json.loads(text, object_pairs_hook=_pairs), dupes[0]
    except Exception:
        return None, False


def mask_body(text, sid):
    """请求体脱敏（JSON 感知 + 就地替换），扩展链路的请求打码入口。

    与代理路径的三级回写同源，目标是**别把客户端 body 的前缀整体挪位**：
    1. `json.loads` 成对象 → `_mask_tree` 逐字符串叶子脱敏（协议位置跳过、业务区强制扫描）；
    2. 首选 `_splice_mask` 在**原始文本上就地替换**（保住排版/转义风格），
       并以 `json.loads(结果) == 脱敏后的树` 等价校验拦下过度替换；
    3. 校验不过（或未 splice）退回整棵重序列化，separators 用紧凑形态。
    解析失败（纯文本体）走 `mask()` 整段扫描。

    零命中时**逐字节原样返回**（省一次序列化，也让上游前缀缓存能命中）。
    例外是**含重复键**的体：树里已丢掉被覆盖的那个值，零改写会放行原文，
    所以强制走重序列化（见 `_load_json_pairs`）。

    深度超限等异常**向上抛**（端点转 (A) 阻断），绝不在这里静默放行明文。
    """
    if not text:
        return text
    obj, has_dupes = _load_json_pairs(text)
    if has_dupes and not _DUP_KEY_WARNED[0]:
        _DUP_KEY_WARNED[0] = True
        try:
            _log("[mask] 请求体存在重复键：该请求已改为整棵重序列化，"
                 "被覆盖的字段值不会明文上行（首次告警，后续静默）")
        except Exception:
            pass
    if not isinstance(obj, (dict, list)):
        # 非 JSON 体（含合法 JSON 标量）：整段当纯文本扫描
        out = mask(text, sid)
        _seed_known(out, sid)
        return out

    changed = [False]
    masked_root = _mask_tree(obj, sid, flag=changed)
    if not changed[0] and not has_dupes:
        # 零改写：一个字都不动（保住前缀），但仍登记历史遗留占位符供响应侧还原
        _seed_known(text, sid)
        return text

    masked_raw = None
    if not has_dupes:
        try:
            spliced = _splice_mask(
                text.encode("utf-8"), masked_root,
                {o: t for o, t in (sessions.get(sid, {}).get("fwd") or {}).items() if t},
            )
        except Exception:
            spliced = None
        if spliced is not None:
            try:
                decoded = spliced.decode("utf-8")
                if json.loads(decoded) == masked_root:
                    masked_raw = decoded
            except Exception:
                masked_raw = None
    if masked_raw is None:
        masked_raw = json.dumps(masked_root,
                               ensure_ascii=("\\u" in text),
                               separators=(",", ":"))
    _seed_known(masked_raw, sid)
    return masked_raw


_logger = logging.getLogger("llm_shield")


def _log(msg):
    """引擎日志。

    mitmproxy 11 起移除了 `ctx.log`，addon 必须用标准 logging（mitmproxy 会把
    root logger 接到自己的日志输出）。此前这里调 `ctx.log.info` 抛 AttributeError
    被下面的 except 吞掉，导致「流式接管」「压缩退化」等全部诊断日志静默丢失，
    断流问题无法归因。异常仍然吞掉：日志失败不能影响代理转发。
    """
    try:
        _logger.info(msg)
    except Exception:
        pass


def _client_source(flow):
    conn = getattr(flow, "client_conn", None)
    peer = None
    for attr in ("peername", "address"):
        value = getattr(conn, attr, None)
        if callable(value):
            try:
                value = value()
            except Exception:
                value = None
        if value:
            peer = value
            break
    if not peer:
        return {}
    if isinstance(peer, (list, tuple)) and len(peer) >= 2:
        host, port = str(peer[0]), peer[1]
    else:
        text = str(peer)
        if ":" not in text:
            return {"client": text}
        host, port = text.rsplit(":", 1)
    try:
        port = int(port)
    except Exception:
        return {"client": f"{host}:{port}", "client_host": host}
    return {"client": f"{host}:{port}", "client_host": host, "client_port": port}


def _emit(typ, **kw):
    try:
        line = "SHIELD\t" + typ + "\t" + json.dumps(kw, ensure_ascii=False)
    except Exception:
        # 事件字段含不可序列化值（理论上不出现）：降级为仅记类型，不让异常穿透代理主流程
        line = "SHIELD\t" + typ + "\t{}"
    _log(line)
    try:
        enqueue_event({"ts": time.time(), "type": typ, **kw})
    except Exception:
        pass


# ========== 2.0 审计钩子（隔离保证：永不改 body，永不抛异常，关时零开销） ==========
def _hash_body(content):
    try:
        if not content:
            return ""
        return hashlib.sha256(content).hexdigest()[:16]
    except Exception:
        return ""


def _audit_response(flow, sid, host, method, path, source, streamed_text=None):
    """响应审计：在 restore 完成后调用。只读不改 body，异常静默。"""
    if not AUDIT_ENABLED:
        return
    try:
        resp = flow.response
        if resp is None:
            return
        status_code = getattr(resp, "status_code", None) or 0
        ct = resp.headers.get("content-type", "")
        # 流式接管时 flow.response.content 不可用（设置会破坏流），用回调累积文本
        if streamed_text is not None:
            content = streamed_text.encode("utf-8")
        else:
            content = resp.content or b""
        body_text = content.decode("utf-8", errors="replace") if content else ""
        # 审计扫描的**输入上限**（审计 M1）。此前全量 body_text 直接喂给
        # `scan_error_leak` / `scan_response_poison` / `scan_dangerous_action`，
        # 而上游完全可以回一个 4xx + 几百 KB 的畸形 body：单是 PEM 正则的
        # 灾难性回溯就足以把 mitmproxy 事件循环 CPU 打满（实测 12KB 就要 3.4s）。
        # 响应侧扫描是**防御性**功能，前段命中已覆盖绝大多数幻觉/泄漏场景。
        # ⚠️ 只截断送给扫描器的副本：`body_text` 本身要保持全量，
        # `_parse_response_payload`（SSE/JSON 结构化解析）不能吃截断后的文本。
        scan_text = body_text[:_SCAN_BODY_MAX] if body_text else ""
        # 回声抑制用的请求体文本：请求里本来就有的危险命令/凭据不算「上游注入」。
        # 生产库实测这是最有效的一条去噪规则——编程助手的对话里 rm、curl|sh
        # 天天出现，只有上游凭空多出来的那条才值得报。
        try:
            req_text = (getattr(flow.request, "content", None) or b"").decode("utf-8", errors="replace")
        except Exception:
            req_text = ""
        scan_req_text = req_text[:_SCAN_BODY_MAX] if req_text else ""
        req_hash = _hash_body(getattr(flow.request, "content", None))
        resp_hash = _hash_body(content)
        common = {
            "sid": sid, "host": host, "method": method, "path": path,
            "request_hash": req_hash, "response_hash": resp_hash,
        }
        findings = []

        # S1 error_leak（被动+主动）
        if AUDIT_SIGNALS.get("error_leak") and status_code >= 400:
            hdrs_text = " ".join(f"{k}:{v}" for k, v in resp.headers.items())
            # 上游域名检测已移除（2026-08-18）：错误页出现用户**已配置**的上游地址
            # 是诊断信息而不是面向客户端的信息泄露，改由普通 ERR/状态日志排障；
            # 留在这里只会把审计中心刷成上游错误页的噪音场。
            findings.extend(_audit.scan_error_leak(status_code, scan_text, hdrs_text))

        # S6 response_poison（被动+主动，200/4xx 都扫）
        if AUDIT_SIGNALS.get("response_poison") and scan_text:
            findings.extend(_audit.scan_response_poison(scan_text, scan_req_text))

        # S9 dangerous_action：模型下发的破坏性命令（rm -rf / / DROP DATABASE / 强推…）
        # 必须扫**还原后**的文本：占位符状态下路径和主机名都是假的，判不准也没意义。
        # 只告警不阻断——设计取舍见 audit_signals.scan_dangerous_action 的注释。
        if AUDIT_SIGNALS.get("dangerous_action") and scan_text:
            findings.extend(_audit.scan_dangerous_action(scan_text, scan_req_text))

        # S2 identity_swap + S4 sse_anomaly：需解析 body
        if body_text and ("json" in ct or "event-stream" in ct):
            # 单次解析产出 (text_chunks, model_field, events) — 避免三重解析
            text_chunks, model_field, events = _parse_response_payload(body_text, ct)
            if AUDIT_SIGNALS.get("identity_swap"):
                # 对比式检测（借鉴 LiteLLM requested_model vs response_model）：
                # 请求 model 是基准真相，响应 model 与之对比，不一致才是换芯——
                # 零知识库、零硬编码，模型迭代/新厂商自动适配。
                req_model = ""
                try:
                    req_body = json.loads(flow.request.content or b"")
                    req_model = _extract_model(req_body)
                except Exception:
                    pass
                # ⚠️ 必须**只调一次**，不能放在 `for chunk in text_chunks` 里（审计 B4）。
                # `scan_identity_swap` 的判据只有 `model_field` + `req_model`，第一个
                # 参数（文本）完全不参与判定（见 audit_signals.scan_identity_swap）。
                # 放进循环的后果是：tool_use-only / reasoning-only / 空文本响应
                # （Anthropic 非流式 tool_use、流式 delta.partial_json、OpenAI
                # content:null 拒答）的 `text_chunks` 为空 → 整段跳过 → 换芯检测
                # 在编程助手最主流的响应形态上完全失效，而 `model_field` 明明已解析出来。
                # 传第一个非空 chunk 只是为了将来若该参数被启用时仍有上下文。
                findings.extend(_audit.scan_identity_swap(
                    text_chunks[0] if text_chunks else "", model_field, req_model))
            # S4 sse_anomaly（仅 SSE）
            if AUDIT_SIGNALS.get("sse_anomaly") and "event-stream" in ct:
                findings.extend(_audit.scan_sse_anomaly(events))

        # S7 cross_request_pollution：仅主动探针模式。
        # 当前请求自身携带的 nonce（current）不算「前序」；只有**没有携带任何
        # nonce 的独立请求**响应里出现前序 nonce，才证明 relay 跨请求存了数据。
        # S5「当前请求回显」已于 2026-08-18 移除：nonce 经 X-Shield-Canaries 头
        # 注入且转发前被剥离，模型本看不到它；若探针还要求模型回显，正常模型
        # 也会回显，不能证明泄漏。
        if AUDIT_ACTIVE_PROBES and body_text:
            current = set(flow.metadata.get("audit_canaries") or set())
            # registry 是 dict {nonce: ts}，取 key 集合做 prior
            prior = set(_AUDIT_CANARY_REGISTRY.keys()) - current
            if AUDIT_SIGNALS.get("cross_request_pollution") and prior:
                findings.extend(_audit.scan_cross_request_pollution(body_text, prior))

        # S3 tool_call_rewrite：仅主动探针模式，由 audit_engine 直接判定（需 expected 对照）
        # 此处被动模式跳过（无法区分正常 tool_call 与被改写的）

        # 写库（按 severity_floor 过滤）
        # 先跨信号去重：identity_swap 是逐 chunk 扫的，SSE 一条回复几百个 delta，
        # 同一句「我是 XX」会在多个 chunk 里各命中一次，不去重就是几百条相同告警。
        findings = _audit.dedupe_findings(findings)
        floor = AUDIT_SEVERITY_FLOOR or "MEDIUM"
        probe_id = flow.metadata.get("probe_id")
        for f in findings:
            if not _audit.severity_ge(f.get("severity", _audit.LOW), floor):
                continue
            enqueue_audit_event({
                **common,
                "signal_type": f.get("signal", ""),
                "severity": f.get("severity", "LOW"),
                "evidence": f.get("evidence", ""),
                "probe_id": probe_id,
            })
            # 审计信号 fail-closed（默认关）：CRITICAL 信号触发时自动停用该 upstream
            # 产品定位是脱敏代理，检测到上游确凿在窃取数据却继续放行逻辑上不自洽（审计规则专项 P2）
            if AUDIT_FAIL_CLOSED and _audit.severity_ge(f.get("severity", _audit.LOW), _audit.CRITICAL):
                # 阻断必须留痕：BLOCK 主事件计入首页 alerts（BLOCK 口径），
                # 此前该路径只有一行 _log，用户盯着 Dashboard 的告警数完全看不到。
                # evidence 已过 _redact_evidence 掩码/摘要（sha256），截断后落 BLOCK，
                # 不含响应正文原文；upstream 只记配置名（flow.metadata 里的 name），不记 URL。
                _emit("BLOCK",
                      reason="audit_critical_signal",
                      signal=str(f.get("signal", "")),
                      severity=str(f.get("severity", "")),
                      evidence=str(f.get("evidence", ""))[:200],
                      sid=sid, host=host, method=method, path=path.split("?")[0],
                      upstream=flow.metadata.get("shield_upstream") or "",
                      **source)
                flow.response = http.Response.make(
                    503, b'{"error":{"code":"shield_audit_blocked"}}',
                    {"Content-Type": "application/json"}
                )
                # _log 只收一个参数；这里原来写的是 _emit_log(msg, "warn")——
                # 该函数在本模块根本不存在，NameError 被外层 except 吞掉，
                # 结果 fail-closed 这条最该留痕的路径反而一行日志都没有。
                _log(f"[audit] fail-closed 阻断：{f.get('signal')} ({str(f.get('evidence', ''))[:80]})")
                break
    except Exception:
        # 审计失败永不影响流量
        return


def _parse_response_payload(body_text, ct):
    """单次解析 JSON/SSE body，产出 (text_chunks, model_field, events)。

    替代原 _extract_response_text + _extract_model_field + _parse_sse_events 三函数，
    避免对同一 body 三重 split + json.loads。
    """
    chunks = []
    model_field = None
    events = []
    is_sse = "event-stream" in ct
    is_json = "json" in ct
    if not body_text or not (is_sse or is_json):
        return chunks, model_field, events
    try:
        if is_sse:
            for line in body_text.split("\n"):
                if not line.startswith("data:"):
                    continue
                # SSE 规范里 `data:` 后的空格是**可选**的（`data:foo` 与 `data: foo` 等价）。
                # 旧实现要求 `data: ` 带空格，且用硬编码偏移 `line[6:]` 取载荷，于是
                # 不带空格的上游（部分网关的 SSE 实现）在 S2/S4 审计里被整段静默跳过
                # （审计 L1）。改成按规范剥掉至多一个前导空格。
                # ⚠️ 只影响审计侧：流式还原走的是另一套解析，本来就不带空格。
                payload = line[5:].lstrip(" ")
                payload = payload.rstrip("\r")
                if payload.strip() == "[DONE]":
                    continue
                try:
                    data = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                etype = data.get("type")
                events.append({"type": etype, "data": data})
                # model_field from message_start（取首个，恢复旧 _extract_model_field 语义）
                if etype == "message_start" and model_field is None:
                    msg = data.get("message") or {}
                    model_field = msg.get("model") or data.get("model")
                # OpenAI 兼容流式：**每个 chunk 顶层都带 model**，而且没有 `type` 键
                # （OpenAI 格式靠 choices 判别，不写事件名）。只看 message_start 会让
                # model_field 恒为 None → S2 换芯检测在所有 OpenAI 兼容中转上完全失效
                # （gpt-* / deepseek / 各类聚合网关，恰恰是换芯最高发的路径）。
                if model_field is None and isinstance(data, dict):
                    mf = data.get("model")
                    if isinstance(mf, str) and mf.strip():
                        model_field = mf
                # text chunks: Claude content_block_delta
                if etype == "content_block_delta":
                    txt = data.get("delta", {}).get("text", "")
                    if txt:
                        chunks.append(txt)
                # text chunks: OpenAI delta
                for c in data.get("choices", []):
                    d = c.get("delta", {})
                    if isinstance(d.get("content"), str):
                        chunks.append(d["content"])
        else:  # json
            data = json.loads(body_text)
            model_field = data.get("model")
            # OpenAI chat
            for c in data.get("choices", []):
                msg = c.get("message", {})
                if isinstance(msg.get("content"), str):
                    chunks.append(msg["content"])
                elif isinstance(msg.get("content"), list):
                    for p in msg["content"]:
                        if isinstance(p, dict) and isinstance(p.get("text"), str):
                            chunks.append(p["text"])
                for tc in msg.get("tool_calls", []):
                    args = tc.get("function", {}).get("arguments", "")
                    if args:
                        chunks.append(args)
            # Anthropic
            if isinstance(data.get("content"), list):
                for b in data["content"]:
                    if isinstance(b, dict) and isinstance(b.get("text"), str):
                        chunks.append(b["text"])
            if isinstance(data.get("output_text"), str):
                chunks.append(data["output_text"])
            # OpenAI Responses API 非流式
            if isinstance(data.get("output"), list):
                for item in data["output"]:
                    if isinstance(item, dict) and isinstance(item.get("content"), list):
                        for blk in item["content"]:
                            if isinstance(blk, dict) and isinstance(blk.get("text"), str):
                                chunks.append(blk["text"])
    except Exception:
        # 解析失败退回整 body（仅 identity 扫描用）
        chunks = [body_text[:2000]]
    return chunks, model_field, events


def _sweep():
    now = time.time()
    # in-flight 会话（请求已发出、响应未到）默认跳过 TTL 回收：长生成可能远超
    # SESSION_TTL，提前删会让响应到达时查不到 rev → 占位符泄漏（P1-2）。
    #
    # 但豁免不能是无限期的：流式路径的 _finish()/_drop() 只在收到空块时触发，
    # 上游中途断连、连接被中间设备静默丢弃时空块永不到达，error 钩子也未必
    # 上报，该会话会带着 inflight=True 和脱敏原文映射永久驻留内存（实测复现）。
    # 因此再加一道硬上限：ts（每个流块由 _touch 刷新）静默超过 _INFLIGHT_MAX_IDLE
    # 即视为连接已死，强制回收。正常长生成只要还在收数据就会持续 _touch，不受影响。
    dead = []
    for sid, s in sessions.items():
        idle = now - s["ts"]
        if s.get("inflight"):
            if idle > _INFLIGHT_MAX_IDLE:
                dead.append(sid)
        elif idle > SESSION_TTL:
            dead.append(sid)
    for sid in dead:
        _drop(sid)
    # 清理过期 canary nonce（按 TTL + 上限）
    if _AUDIT_CANARY_REGISTRY:
        expired = [n for n, ts in _AUDIT_CANARY_REGISTRY.items() if now - ts > _AUDIT_REGISTRY_TTL]
        for n in expired:
            _AUDIT_CANARY_REGISTRY.pop(n, None)
        # 超上限清最早（按 ts 升序）
        if len(_AUDIT_CANARY_REGISTRY) > _AUDIT_REGISTRY_MAX:
            sorted_items = sorted(_AUDIT_CANARY_REGISTRY.items(), key=lambda kv: kv[1])
            for n, _ in sorted_items[:len(_AUDIT_CANARY_REGISTRY) - _AUDIT_REGISTRY_MAX]:
                _AUDIT_CANARY_REGISTRY.pop(n, None)


def error(flow):
    """连接/上游异常兜底：清会话 + 按类型记录事件。

    按错误性质区分事件类型（曾全部记 ERR 计入 alerts，正常操作也被当异常）：
    - Client disconnected：客户端主动断开（IDE 按 ESC/切换话题/关窗口），
      正常操作，记 CANCEL（不进 alerts，日志仍可见）
    - getaddrinfo failed：上游域名解析临时失败（多为上游断连后的重连期），
      记 DNS_ERROR（不进 alerts，属上游侧）
    - 其余（server closed connection / 上游重置等）：记 ERR（计入 alerts）
    """
    sid = flow.metadata.get("session_id")
    try:
        host = getattr(flow.request, "host", None) or getattr(flow.request, "pretty_host", "")
        path = flow.metadata.get("shield_orig_path") or getattr(flow.request, "path", "")
        s = sessions.get(sid, {}) if sid else {}
        source = s.get("source", {})
        err = getattr(flow, "error", None)
        msg = ""
        try:
            msg = str(err)[:160]
        except Exception:
            pass
        if not (sid or msg):
            return
        ev_type = "ERR"
        if "Client disconnected" in msg:
            ev_type = "CANCEL"  # 用户主动取消，非故障
        elif "getaddrinfo" in msg or "Name or service not known" in msg:
            ev_type = "DNS_ERROR"  # 上游域名解析失败，属上游侧
        # 流式接管中途被切断时 _finish() 不执行，没有 RESTORE 事件可对照，
        # 光看 ERR 无法判断断在哪。带上回调次数/字节数还原现场。
        if flow.metadata.get("shield_streamed"):
            msg = (f"[stream calls={flow.metadata.get('shield_stream_calls')} "
                   f"bytes={flow.metadata.get('shield_stream_bytes')}] " + msg)
        # 走了出口代理的请求，失败时必须标出来：代理不通与上游不通的现象一样
        # （连接超时/被拒），不标注就分不清该查代理还是查上游。
        if flow.metadata.get("shield_via_proxy"):
            msg = "[via egress_proxy] " + msg
        up_name = flow.metadata.get("shield_upstream") or (s.get("upstream_name") if s else "") or ""
        model = flow.metadata.get("shield_model") or (s.get("model") if s else "") or ""
        _emit(ev_type, host=host or "", method=getattr(flow.request, "method", "") or "",
              path=path.split("?")[0] if isinstance(path, str) else "",
              sid=sid or "", msg="flow_error:" + msg,
              upstream=up_name, model=model, **source)
    except Exception:
        pass
    if sid:
        _drop(sid)


# ========== mitmproxy hooks ==========


def _clean_tool_enums(body):
    """清洗 tools schema：删除 enum 数组中的非字符串值。

    OpenAI 规范允许 enum 为任意 JSON 值，但 Gemini function_declarations
    要求 enum 是字符串数组；部分中转站/上游转换 tools 时对非字符串 enum
    直接 400 或流式中断（实测 pi 的 subagent 工具 enum 含 False/1）。
    enum 仅作取值提示，删除后不影响 schema 合法性，模型照常生成参数。

    过滤后为空必须**整个删掉 enum 键**，不能留 `enum: []`：空数组的语义是
    「该参数没有任何合法取值」，比不带 enum 更糟——模型会认为无法构造合法
    参数而干脆不调用该工具。boolean/integer 类型的 enum 天然全是非字符串
    （如 `{"type":"boolean","enum":[true,false]}`），是最常见的命中场景。

    返回值：body 是否真的被改动过。调用方据此决定要不要回写请求体 ——
    没改就一个字都不动，保住上游前缀缓存（见 `_mask_hit`）。
    """
    changed = False
    try:
        tools = body.get("tools") if isinstance(body, dict) else None
        if not isinstance(tools, list):
            return False

        def clean(obj):
            nonlocal changed
            if isinstance(obj, dict):
                if isinstance(obj.get("enum"), list):
                    kept = [x for x in obj["enum"] if isinstance(x, str)]
                    if kept:
                        if len(kept) != len(obj["enum"]):
                            changed = True
                        obj["enum"] = kept
                    else:
                        obj.pop("enum", None)  # 全非字符串：删键，不留空数组
                        changed = True
                for v in obj.values():
                    clean(v)
            elif isinstance(obj, list):
                for v in obj:
                    clean(v)

        for t in tools:
            clean(t)
    except Exception:
        pass
    return changed

def _clean_reasoning_effort(body, up_name):
    """标记 reasoning_effort 可疑值，不做删除——透明代理不改下游请求。

    实测根因：pi 在 thinking=off 时发 `reasoning_effort: "none"`（识图等扩展
    调用 mimo-v2.5 时必然携带），部分中转上游只认
    low/medium/high，其余值 400 Bad Request——表现为「同样的请求手动 200、
    插件 400」的假象。这本质是**下游模型配置问题**（pi 的 thinkingLevelMap
    把 off 映射成 "none"），不应由代理删字段掩盖：删字段会改变用户显式
    配置的思考强度语义，且不同模型/上游对取值支持不同，误伤面不可控。
    正确做法：请求原样透传（上游 400 就如实返回），同时标记可疑值，
    事件/面板提示「reasoning_effort=xxx 可能不被上游支持」，引导下游
    排查模型配置（pi 侧改 thinkingLevelMap off→None 即可，实测已生效）。
    返回可疑值字符串（供错误提示用），无则返回 None。
    """
    try:
        if not isinstance(body, dict):
            return None
        re_ = body.get("reasoning_effort")
        if re_ is None:
            return None
        if isinstance(re_, str) and re_ in ("low", "medium", "high"):
            return None
        # 非 low/medium/high（none/minimal/max/非字符串等）：标记，不改请求
        return str(re_) if not isinstance(re_, str) else re_
    except Exception:
        return None


def _reasoning_effort_hint(reasoning_value):
    """生成 reasoning_effort 可疑值的排查提示文案（供事件 msg 用）。"""
    if not reasoning_value:
        return ""
    return (f"reasoning_effort={reasoning_value} 可能不被上游支持"
            f"（部分中转上游仅支持 low/medium/high）；"
            f"请检查客户端模型配置的思考强度映射（pi 侧 thinkingLevelMap off→None）")


def request(flow: http.HTTPFlow):
    _maybe_reload()  # 热重载：加词即时生效
    method = getattr(flow.request, "method", "") or ""
    source = _client_source(flow)
    orig_host = flow.request.pretty_host
    orig_path = flow.request.path

    # 反向代理模式：按 base_path 路由到真实上游，剥掉前缀，改写 host/scheme/port
    matched_up = None
    if CAPTURE_MODE == "reverse":
        flow.metadata["shield_orig_path"] = orig_path
        matched_up, final_path = apply_reverse_routing(flow)
        if not matched_up:
            _emit_skip(orig_host, method, orig_path, "no_reverse_route", source=source)
            flow.response = http.Response.make(404, b'{"error":"no_reverse_route"}', {"content-type": "application/json"})
            return
        # 路由后用最终路径和真实上游 host 判断是否为目标 LLM API
        host = getattr(flow.request, "host", None) or orig_host
        path = flow.request.path
        # 非白名单路径不再 404 拦下：/v1/models、/v1/embeddings、健康检查等是客户端
        # 初始化必打的接口，直接拒绝会让人以为代理坏了。这里只决定"是否脱敏"，转发照旧。
        up_name = matched_up.get("name") or ""
        flow.metadata["shield_upstream"] = up_name
        # 客户端级注入请求头（extra_headers）：只注入与凭据无关的协议头
        # （凭据头与占位符/空值都会被 _apply_extra_headers 跳过）。
        # 必须在转发前设置（客户端请求头在 request() 阶段可改）。
        _apply_extra_headers(flow, matched_up)
        # 出口代理必须在任何 return 之前挂上（含下面的 passthrough_unlisted_path 分支）
        _apply_egress_proxy(flow, matched_up)
        if not _upstream_path_ok(matched_up, path):
            if method in _READONLY_METHODS:
                _emit_skip(host, method, path, "passthrough_unlisted_path", source=source, upstream=up_name)
                return
            # 无论是否在白名单，非只读请求只要像 LLM 请求就继续进入脱敏流程；
            # 但若未在白名单路径且并非标准 LLM 文本补全请求：
            # 若是声明非 JSON（如 multipart/form-data 音频上传、二进制流），在 FAIL_CLOSED 下绝不能静默透传，必须阻断；
            # 若是 JSON，FAIL_CLOSED 下**同样不能按 passthrough 放行** —— 见下面 fail_closed 分支的说明。
            if not _looks_like_llm_request(flow):
                ct_unlisted = (flow.request.headers.get("content-type", "") or "").lower()
                # FILTER_ENABLED=False（用户承诺「透明转发」）时不阻断：开关语义
                # 必须完整——关了脱敏还 503 拦 multipart/二进制，等于没关（审计 P2）。
                if "json" not in ct_unlisted and FAIL_CLOSED and FILTER_ENABLED:
                    _emit("BLOCK", host=host, method=method, path=path.split("?")[0],
                          reason="unlisted_non_json_blocked", upstream=up_name, **source)
                    flow.response = http.Response.make(
                        503,
                        json.dumps({"error": "shield_mask_failed", "reason": "unlisted_non_json_blocked"},
                                   ensure_ascii=False).encode("utf-8"),
                        {"content-type": "application/json"},
                    )
                    return
                # 请求已经落在用户配置的上游路由上（matched_up 为真），此时
                # 「形态不认识」在 FAIL_CLOSED 下必须交给主管线按 unknown_shape
                # 脱敏，不能凭「路径不在白名单」就把原文放出去。
                #
                # 原因（外部审计 SHIELD-UNLISTED-PASSTHROUGH-001）：放行判据是
                # _LLM_BODY_KEYS，而它是**白名单**，永远追不上新协议（实测 Cohere
                # v1 chat / Bedrock Titan / 讯飞星火 都曾整包透传原文）。主管线
                # L3080 对同样的形态是「配置路由 + fail_closed → 一律脱敏」；这里若
                # 放行，fail_closed 的承诺就取决于**路径在不在白名单**，而不取决于
                # fail_closed 本身。实测可达：未配 paths 时白名单只有 7 条默认路径，
                # POST /v1/vector_stores、/v1/fine_tuning/jobs、/v2/chat、以及任意
                # 厂商新端点 {"text":"张三 13800138000 …"} 都会明文上行。
                #
                # 走主管线还顺带消掉一个倒挂：_looks_like_llm_request 对「声明 JSON
                # 但解析失败」返回 True（交 fail_closed 脱敏），对「解析成功但键不
                # 认识」返回 False（放行） —— 原本解析失败反而比解析成功更安全。
                if not FAIL_CLOSED:
                    _emit_skip(host, method, path, "passthrough_unlisted_path", source=source, upstream=up_name)
                    return
    else:
        host = orig_host
        path = orig_path
        if not is_target(host, path):
            _emit_skip(host, method, path, _target_miss_reason(host, path) or "not_target", source=source)
            return
        up_name = ""

    up_name = (matched_up or {}).get("name") or flow.metadata.get("shield_upstream") or ""

    # 只读方法没有请求体，无需脱敏，直接转发 —— 仍记 PASS（过网关必有日志）
    if method in _READONLY_METHODS:
        _emit_skip(host, method, path, "readonly_method", source=source, upstream=up_name)
        return

    # 过滤开关关闭：路由已生效（reverse 模式已改写 host），但不脱敏，透明转发到上游
    if not FILTER_ENABLED:
        flow.metadata["shield_filter_off"] = True
        # 声明 identity：否则上游对 SSE 压缩后，responseheaders 的流式接管只能
        # 退回整包路径，客户端失去打字机效果（与脱敏路径 3592 的处理一致；
        # 代价是过滤关闭期间非流式 JSON 响应也不压缩，PT 兜底层同样如此）。
        if STREAM_RESPONSE and "json" in (flow.request.headers.get("content-type", "") or "").lower():
            flow.request.headers["accept-encoding"] = "identity"
        _emit(
            "BYPASS",
            host=host, method=method,
            path=orig_path.split("?")[0] if CAPTURE_MODE == "reverse" else path.split("?")[0],
            reason="filter_disabled",
            upstream=up_name, **source,
        )
        return

    ct = (flow.request.headers.get("content-type", "") or "").lower()
    if "json" not in ct:
        # 声明非 JSON（multipart 上传、二进制等）：脱敏管线处理不了。
        # fail_closed 下阻断（无法确认里面没有原文）；仅排查问题时
        # 可关 fail_closed 放行，此时记 BYPASS 让用户在日志里看得见。
        if FAIL_CLOSED:
            _emit("BLOCK", host=host, method=method, path=path.split("?")[0],
                  reason="non_json_body", content_type=str(ct or "")[:80],
                  upstream=up_name, **source)
            flow.response = http.Response.make(
                503,
                json.dumps({"error": "shield_mask_failed", "reason": "non_json_body"},
                           ensure_ascii=False).encode("utf-8"),
                {"content-type": "application/json"},
            )
            return
        _emit(
            "BYPASS", host=host, method=method, path=path.split("?")[0],
            reason="non_json_body", content_type=str(ct or "")[:80],
            upstream=up_name, **source,
        )
        return
    try:
        raw_content = flow.request.content or b""
    except Exception:
        raw_content = b""
    # 体积闸门放在 json.loads 之前：解析本身对超大 body 同样昂贵，且一样阻塞
    # event loop。超限一律拒绝（不看 fail_closed）——放行等于把原文原样上行，
    # 正是脱敏代理绝不能做的事。
    if len(raw_content) > _MAX_REQUEST_BODY:
        _emit("BLOCK", host=host, method=method, path=path.split("?")[0],
              reason="request_too_large", bytes=len(raw_content),
              upstream=up_name, **source)
        flow.response = http.Response.make(
            413,
            json.dumps({"error": "shield_request_too_large",
                        "reason": "request_too_large",
                        "limit_bytes": _MAX_REQUEST_BODY}, ensure_ascii=False).encode("utf-8"),
            {"content-type": "application/json"},
        )
        return
    # 重复键（{"a":"13800138000","a":"safe"}）：json.loads 取后者覆盖前者，树里
    # 已经丢了被覆盖的值，扫不到 → 零改写分支会放行原始字节（审计 B2 实测）。
    # 检出后强制走重序列化，并禁用 splice（见下方回写分支）。
    body, has_dup_keys = _load_json_pairs(raw_content)
    if body is None:
        # 声明了 JSON 却解析不了：无法确认里面没有原文。fail_closed 下必须拦。
        if FAIL_CLOSED:
            _emit("BLOCK", host=host, method=method, path=path.split("?")[0], reason="invalid_json", upstream=up_name, **source)
            flow.response = http.Response.make(
                400,
                json.dumps({"error": "shield_invalid_json", "reason": "invalid_json"}, ensure_ascii=False).encode("utf-8"),
                {"content-type": "application/json"},
            )
            return
        _emit_skip(host, method, path, "invalid_json", ct, source=source, upstream=up_name)
        return
    if has_dup_keys and not _DUP_KEY_WARNED[0]:
        _DUP_KEY_WARNED[0] = True
        try:
            _log("[mask] 请求体存在重复键：该请求已改为整棵重序列化，"
                 "被覆盖的字段值不会明文上行（首次告警，后续静默）")
        except Exception:
            pass
    # 顶层不是对象（JSON 数组/字符串/数字）。没有任何主流 LLM API 用这种形态，
    # 但它完全可能载有原文——["手机号 13800138000"] 就是一次完整的泄漏。
    # 曾在这里直接 _emit_skip 放行，与相邻两个分支（non_json_body / invalid_json
    # 在 fail_closed 下都阻断）不一致，也与 fail_closed「绝不放行原文上行」的承诺
    # 冲突（SHIELD-NONOBJECT-BYPASS-001）。
    # 这里不阻断而是照常脱敏：_mask_tree 对 list/str/标量一样有效，脱敏比 400 更不
    # 容易误伤用户自建的非标准接口。做法是套一层合成根键让下游的 dict 逻辑照常跑，
    # 发往上游前再拆掉，上游看到的仍是原来的形态。
    root_is_object = isinstance(body, dict)
    if not root_is_object:
        body = {_ROOT_WRAP_KEY: body}
    unknown_shape = False
    stream_mode = "stream" if body.get("stream") is True else "non_stream"
    # 非 LLM 形态 JSON（无 messages/prompt 等特征键）。
    # 形态不认识 ≠ 没有原文：_LLM_BODY_KEYS 是白名单，而白名单永远追不上新协议
    # （实测 Cohere v1 chat / Bedrock Titan / 讯飞星火 都曾整包透传原文）。
    # 所以这里按「请求有没有落在用户显式配置的上游路由上」分流：
    #   - 在配置好的路由上 + fail_closed：一律脱敏，只把「形态不认识」记进事件供排查。
    #     用户把 /v1 路由到某个模型服务商，本来就意味着这条链路上的请求体要当正文对待。
    #   - 用户主动关了 fail_closed：保持原行为，记 PASS 不脱敏。
    #
    # 判据用 CAPTURE 模式各自的「已配置」证据，不用 up_name（2026-08-17 外部审计）：
    # up_name 只在 reverse 模式有值，explicit/local 恒为 ""，于是
    # `FAIL_CLOSED and up_name` 必然 falsy —— **那两个模式无论 fail_closed 开没开
    # 都直接放行原文上行**，与「fail-closed 绝不放行原文」的承诺直接冲突。
    # 顺带修掉第二个隐患：reverse 模式下 upstream 名字留空时 up_name 也是 ""，同样绕过。
    #
    # 走到这一行时两种模式都已经证明在配置好的路由上：
    #   reverse       —— matched_up 为真，否则前面已 404 返回
    #   explicit/local —— is_target(host, path) 为真（域名与路径都命中用户配置），
    #                     否则前面已 _emit_skip("not_target") 返回
    # 所以这里只需要看 fail_closed 本身。
    if root_is_object and not _looks_like_llm_request(flow) and not any(k in body for k in _LLM_BODY_KEYS):
        if not FAIL_CLOSED:
            _emit_skip(host, method, path, "non_llm_json", ct, source=source, upstream=up_name)
            return
        unknown_shape = True
    # 流式请求禁止上游压缩：压缩后的 SSE 在 responseheaders 阶段仍是压缩字节，
    # 无法按事件切分，只能退回整包路径 —— 客户端就此失去流式效果（首字延迟=整段
    # 生成时长）。这里主动声明 identity，把「能不能流式」从上游的压缩策略里解耦。
    # 非流式请求不动，保留压缩节省带宽。置于 LLM 形态判断之后：非 LLM 请求不白改。
    if stream_mode == "stream" and STREAM_RESPONSE and host not in STREAM_EXCLUDE_HOSTS:
        flow.request.headers["accept-encoding"] = "identity"

    # 清洗 tools schema 的 enum 非字符串值（Gemini function_declarations 兼容）。
    # 仅限已知中转渠道（实测其 tools 转换器拒绝非字符串 enum）
    # 且模型为 gemini 系列（Google API 校验 enum 类型，其他模型原生 API 不校验）；
    # 其余渠道/模型不做改动，保持原生 schema。
    # enum 清洗对任何上游都是无损操作（enum 仅取值提示），官方三渠道原生 API
    # 校验宽松可不改；中转渠道的 tools 转换器拒绝非字符串 enum（实测），
    # 故对所有非官方渠道 + gemini 模型启用。
    enum_changed = False
    if up_name not in ("openai", "deepseek", "anthropic") and str(body.get("model", "")).startswith("gemini"):
        enum_changed = _clean_tool_enums(body)
    # 标记 reasoning_effort 可疑值（不修改请求）：上游 400 时在事件里提示
    # 下游排查模型配置（pi 的 thinkingLevelMap off→"none" 曾导致识图 400）
    flow.metadata["shield_reasoning_effort"] = _clean_reasoning_effort(body, up_name)
    _sweep()
    # 16 位十六进制 = 64 bit。原来取 8 位（32 bit），生日碰撞在实测里 1 万请求还是
    # 0 次、2 万就到约 4.6%、10 万约 69%——重度用户一天就能跑到那个量级，
    # 而 sid 碰撞意味着两个会话的占位符映射串到一起，会把别人的原文还原给你，
    # 属于最严重的一类故障。加宽到 64 bit 后同样 10 万请求碰撞概率约 2.7e-10。
    # sid 只在进程内内存表和事件库里做关联键，加长不影响任何对外协议。
    sid = uuid.uuid4().hex[:16]
    _new_session(sid, source=source)
    flow.metadata["session_id"] = sid
    # 2.0 审计：从请求 header 读 probe_id + canaries（panel 主动探针注入），读完即 strip 不转发上游
    probe_id = flow.request.headers.get("x-shield-probe-id", "") or ""
    if probe_id:
        flow.metadata["probe_id"] = probe_id
        flow.request.headers.pop("x-shield-probe-id", None)
    canary_hdr = flow.request.headers.get("x-shield-canaries", "") or ""
    if canary_hdr:
        nonces = [n for n in canary_hdr.split(",") if n]
        flow.metadata["audit_canaries"] = set(nonces)
        # 注册到全局表（dict {nonce: ts}），按 ts 清理过期
        now = time.time()
        for n in nonces:
            _AUDIT_CANARY_REGISTRY[n] = now
        flow.request.headers.pop("x-shield-canaries", None)

    if DEBUG:
        _raw = flow.request.content or b""
        _debug(f"REQUEST {host}{path.split('?')[0]} -- 原始(未脱敏)", sid,
               _raw.decode("utf-8", errors="replace"))

    # fail-closed：整个脱敏管线包一层，异常时阻断请求（503），绝不放行原文上行。
    # 关闭 fail-closed 仅用于排查问题：异常时记录 ERR 后继续转发（可能泄露原文）。
    # body_rewritten / first_diff_byte 只用于 MASK 事件的诊断，不参与脱敏决策：
    # 用户报「上游缓存命中率归零」时，这两个值能直接区分「我们改了字节」与
    # 「上游自己 miss」，也是决定要不要做字节级替换的唯一实测依据。
    body_rewritten = False
    first_diff_byte = -1
    _mask_t0 = time.perf_counter()
    try:
        # 脱敏前记录扫描范围 + 各角色文本（仅内存，归因用，不落原文）
        scan_scope = _request_scope(body)
        role_texts = _collect_role_texts(body)
        # 递归脱敏所有承载正文的顶层字段。逐格式硬编码会漏掉工具调用参数等嵌套位置，
        # 这里统一走 _mask_tree（内部路径感知：协议位置跳过、业务区强制扫描）。
        # 注意：必须遍历 body 全部顶层 key——曾只处理白名单 key，顶层自定义业务对象
        # （customer 等）整体绕过脱敏（审计验收点"任意 customer.id"实测漏检）。
        # 非字符串/列表/字典（数字/bool/null）_mask_tree 原样返回，无副作用。
        # body_changed 是单元素 list（可变），由 _mask_hit 在真的替换过时置 True。
        body_changed = [False]
        # 顶层**键名**也要过一遍（审计 B2 的「敏感值作键名」）。
        #
        # 为什么之前漏了：这里按顶层 key 逐个取值送进 `_mask_tree`，于是键名本身
        # 一次都没经过 `mask()`。而扩展链路的 `mask_body` 是把整个 body 交给
        # `_mask_tree`（其 dict 分支会脱敏键名）——**同一个 body 走两条链路结果不同**，
        # `{"13800138000": "safe"}` 在扩展链路已打码、在代理链路仍原样上行。
        #
        # 判据与 `_mask_tree` 的 dict 分支**完全一致**（同一个白名单、同一个 `mask()`），
        # 不另立一套，否则两边迟早再漂一次。
        # ⚠️ `_ROOT_WRAP_KEY` 必须原样保留：非对象根（列表根）会被包成
        # `{__shield_root__: [...]}`，键名一旦被改写，下面 `body[_ROOT_WRAP_KEY]`
        # 直接 KeyError → 整个脱敏管线抛异常 → fail-closed 503，所有列表根请求全挂。
        renamed = {}
        for key in list(body.keys()):
            new_key = key
            if (isinstance(key, str) and key != _ROOT_WRAP_KEY
                    and key not in _MASK_PROTECTED_KEY_NAMES):
                masked_key = mask(key, sid)
                if masked_key != key:
                    new_key = masked_key
                    body_changed[0] = True
            # 传进去的仍是**原键**：`_leaf_exempt` 的协议位置判定必须看客户端真实的键名
            # （同 `_mask_tree` dict 分支的注释）。
            renamed[new_key] = _mask_tree(body[key], sid, key, flag=body_changed)
        # 就地替换内容而非给 body 重新绑定：body 是调用方持有的对象，
        # 下面 enum 清洗 / splice / `masked_root` 都还在用它，且要保持键的插入顺序。
        body.clear()
        body.update(renamed)

        # has_dup_keys 必须一起算进脏标记：树里丢了被覆盖的值，判定「没改过」是假的。
        if body_changed[0] or enum_changed or has_dup_keys:
            # 只有真的改过才回写请求体。回写方式分三级，目标都是别把「前缀」整体挪位 ——
            # 上游按前缀做 Prompt Cache，前缀字节一变就整段 miss：
            #   1) 首选**字节级文本替换**（`_splice_mask`）：直接在客户端原始 JSON 文本上
            #      做敏感值占位符替换，客户端 body 的排版（空格、缩进、数字写法、转义风格）
            #      全部原样保留。实测一条带空格 + `\u` 转义的请求：敏感值在 byte 74，
            #      整棵重序列化的差异位却在 byte 9 —— 中间 65 字节的前缀被白白改掉。
            #      由等价校验确保结构正确。见 `_splice_mask`。
            #   2) 替换结果必须通过 `json.loads(结果) == 脱敏后的树` 等价校验才采用；
            #      不过（含 enum 清洗这类结构性改动，splice 表达不了）就退回下一级。
            #   3) 退路是整棵重序列化，两个细节同样为了保前缀：
            #      · separators 用紧凑形态：json.dumps 默认 (", ", ": ") 会在每个
            #        逗号/冒号后插空格，把 SDK 普遍发的紧凑体整体改写（实测 113→123 字节）。
            #      · ensure_ascii 跟随客户端已表现出的策略：正文里出现过 `\u` 转义，
            #        说明客户端用 ensure_ascii=True，我们回写时也转义；否则这次重序列化
            #        会把 `\u5f20\u4e09` 展开成「张三」，凭空扩大与客户端前缀的字节差异。
            # 三级回写的都是**同一棵已经脱敏的树**，所以不存在放行原文的路径。
            masked_root = body if root_is_object else body[_ROOT_WRAP_KEY]
            masked_raw = None
            # has_dup_keys 时禁用 splice：丢掉的重复键不在替换表里，而等价校验
            # （json.loads(spliced) == masked_root）会因为「解析回来仍是那棵折叠后的树」
            # 而误判通过，于是原文里的敏感值被原样带出去。直接重序列化脱敏树。
            if BYTE_SPLICE and not enum_changed and not has_dup_keys:
                try:
                    spliced = _splice_mask(
                        raw_content, masked_root,
                        {o: t for o, t in (sessions.get(sid, {}).get("fwd") or {}).items() if t},
                    )
                except Exception:
                    spliced = None
                if spliced is not None:
                    try:
                        if json.loads(spliced) == masked_root:
                            masked_raw = spliced.decode("utf-8")
                    except Exception:
                        masked_raw = None
            if masked_raw is None:
                masked_raw = json.dumps(
                    masked_root,
                    ensure_ascii=(b"\\u" in raw_content),
                    separators=(",", ":"),
                )
            # 历史里带上来的、上一轮遗留的占位符：登记进本会话，响应侧仍能还原（自愈）
            _seed_known(masked_raw, sid)
            flow.request.content = masked_raw.encode("utf-8")
            body_rewritten = True
            first_diff_byte = _first_diff_byte(raw_content, flow.request.content)
        else:
            # 零改写透传：一个敏感词都没命中，就**一个字都不动** flow.request.content。
            # 除了省一次序列化，更重要的是保证上游收到的字节与客户端发出的完全一致
            # （含分隔符、键序、\u 转义、数字字面量写法），这是 Prompt Cache 命中的前提。
            # _seed_known 照常跑：客户端历史里带来的占位符本轮响应若被模型复述仍要能还原。
            _seed_known(raw_content.decode("utf-8", "replace"), sid)

    except Exception as e:
        _drop(sid)
        emit_path_err = orig_path if CAPTURE_MODE == "reverse" else path
        if FAIL_CLOSED:
            _emit("BLOCK", host=host, method=method, path=emit_path_err.split("?")[0], reason="mask_pipeline_failed", msg=str(e)[:200], upstream=matched_up["name"] if matched_up else "", **source)
            flow.response = http.Response.make(
                503,
                json.dumps({"error": "shield_mask_failed", "reason": "mask_pipeline_failed"}, ensure_ascii=False).encode("utf-8"),
                {"content-type": "application/json"},
            )
            return
        _emit("ERR", host=host, method=method, path=emit_path_err.split("?")[0], sid=sid, msg="mask:" + str(e)[:200], **source)
        return

    if DEBUG:
        _raw2 = flow.request.content or b""
        _debug(f"REQUEST {host}{path.split('?')[0]} -- 脱敏后(发往上游)", sid,
               _raw2.decode("utf-8", errors="replace"))

    fwd = sessions.get(sid, {}).get("fwd", {})
    labels = sessions.get(sid, {}).get("labels", {})
    # 本次实际命中的唯一原文（mask 里累积，跨字符串叶子不覆盖）。
    # hit_count=本次命中数；new_count=其中本次新增的（_hit 在 _remember 前记录）
    last_hits = sessions.get(sid, {}).get("last_hits") or set()
    new_orig = sessions.get(sid, {}).get("new_orig") or set()
    hit_count = len(last_hits)
    new_count = len(last_hits & new_orig)
    items = []
    # 明细上限提到 30：OpenCode 长会话常 >10 命中，截断后无法定位误伤词
    # 优先展示本次命中的项，让 count 与明细对得上
    shown = set()
    hit_items = [o for o in last_hits if o in fwd]
    ordered = list(hit_items) + [o for o in fwd if o not in last_hits]
    for orig in ordered[:30]:
        tok = fwd.get(orig, "")
        if not tok:
            continue
        m = _PLACEHOLDER_PARTS_RX.match(tok)
        label = labels.get(orig, "")
        roles = _hit_roles_for(orig, role_texts)
        # 凭据类标签（CREDENTIAL_LABELS：API_KEY/TOKEN/SECRET/ACCESS_KEY/JWT/CONNSTR/PRIVATE_KEY）永不明文落库：
        # 只存类型 + 打码 preview + 长度 + sha256 摘要（审计要求，v1.5.19 起）。
        # 非凭据 PII 保留 original（项目约定：明文只进详情弹窗，导出/列表用 preview）。
        is_cred = label in CREDENTIAL_LABELS
        item = {
            "tok": tok,
            "label": label,
            "hash": m.group(2) if m else "",
            "length": len(orig),
            "preview": _preview(orig, label),
        }
        if is_cred:
            item["cred"] = True
            item["digest"] = _cred_digest(orig)
        else:
            item["original"] = orig
        if roles:
            item["roles"] = roles[:6]
        if len(orig) <= 2:
            item["short"] = True
        items.append(item)
        shown.add(orig)
    emit_path = orig_path if CAPTURE_MODE == "reverse" else path
    # 对话摘要：只保留 user/assistant 文本，便于日志阅读（不是整包 JSON）
    try:
        dialog = _extract_chat_dialog(flow.request.content, 4000)
    except Exception:
        dialog = ""
    try:
        raw_preview = _body_preview(flow.request.content, 800)
    except Exception:
        raw_preview = ""
    # 落库前凭据清洗：dialog/preview 即使残留凭据形态（SECRET 规则外的变体）也不留明文
    dialog = _redact_credentials(dialog)
    raw_preview = _redact_credentials(raw_preview)
    # 短词命中计数：便于界面提示「过短词误伤」
    short_hits = sum(1 for it in items if it.get("short"))
    model = _extract_model(body)
    try:
        flow.metadata["shield_model"] = model
    except Exception:
        pass
    # model 存入会话：RESTORE 事件（含流式接管路径）从会话读取，避免响应阶段再解析请求体
    try:
        s_sess = sessions.get(sid)
        if s_sess is not None:
            s_sess["model"] = model
            # 标记 in-flight：请求已发出、响应未到，_sweep 不得按 TTL 删本会话
            s_sess["inflight"] = True
            # scan_scope 存入会话：RESTORE 事件要复用（前端归因展示），
            # 避免硬编码猜测「命中来自 system/历史」
            s_sess["scan_scope"] = scan_scope
            # role_texts 供 RESTORE items 归因（_hit_roles_for 需要）
            s_sess["role_texts"] = role_texts
            # 请求对话摘要存入会话：RESTORE 事件带 dialog_req（用户消息），
            # 回复日志弹窗才能显示用户发送的内容（曾 100% 缺失，SHIELD-DIALOG-002）
            s_sess["req_dialog"] = dialog
            s_sess["stream_mode"] = stream_mode
            # 客户端名存入会话：RESTORE 事件复用（曾缺 upstream 字段，
            # 日志列表「客户端」列 MASK 行有值、RESTORE 行空白，显示不统一）
            s_sess["upstream_name"] = matched_up["name"] if matched_up else "" 
            # 脱敏管线耗时（毫秒）：MASK 事件展示，用户可看到代理增加的开销
            s_sess["mask_ms"] = (time.perf_counter() - _mask_t0) * 1000
    except Exception:
        pass
    _emit(
        "MASK",
        host=host,
        method=method,
        path=emit_path.split("?")[0],
        sid=sid,
        count=hit_count,          # 本次实际命中的唯一原文数（含历史复用）
        new_count=new_count,      # 其中本次新增的
        masked_total=len(fwd),    # 会话累计脱敏的唯一值总数（历史会增长）
        items=items,
        upstream=matched_up["name"] if matched_up else "",
        model=model,
        dialog=dialog,
        req_preview=raw_preview,
        scan_scope=scan_scope,
        short_hits=short_hits,
        stream_mode=stream_mode,
        mask_ms=round((time.perf_counter() - _mask_t0) * 1000, 1),
        # 请求体形态：标准 LLM 形态不带该字段；非对象根 / 白名单外形态各记一种，
        # 便于用户在日志里发现「这条是靠兜底脱敏的」并反馈新协议形态。
        **({"body_shape": "non_object_root"} if not root_is_object
           else {"body_shape": "unknown_shape"} if unknown_shape else {}),
        # 前缀诊断（均不含原文）：本次是否回写了请求体、回写后与客户端原始字节的
        # 首个差异位置、命中的占位符是否为复用。用户报「上游缓存命中率归零」时，
        # 这三项能直接区分「我们改了字节」与「上游自己 miss」。
        body_rewritten=body_rewritten,
        first_diff_byte=first_diff_byte,
        suffix_reused=bool(sessions.get(sid, {}).get("suffix_reused")),
        **source,
    )


def response(flow: http.HTTPFlow):
    sid = flow.metadata.get("session_id")
    if not sid:
        return
    # 流式响应已在 stream 回调里逐块还原并收尾，这里不再重复处理
    if flow.metadata.get("shield_streamed"):
        return
    host = getattr(flow.request, "host", None) or flow.request.pretty_host
    path = flow.request.path
    emit_path = flow.metadata.get("shield_orig_path") or path
    method = getattr(flow.request, "method", "") or ""
    # reverse 模式下 host/path 已在 request 阶段改写为真实上游；session_id 存在即为已拦截流量
    if CAPTURE_MODE != "reverse" and not is_target(host, path):
        _drop(sid)
        return
    if not flow.response or not flow.response.content:
        _drop(sid)
        return

    ct = flow.response.headers.get("content-type", "")
    _touch(sid)
    _sweep()
    source = sessions.get(sid, {}).get("source", {})
    # 响应到达时间：整包路径在此刻记（首字节=响应完成）；流式在 _stream 首 chunk 记
    s_cur = sessions.get(sid)
    if s_cur is not None and s_cur.get("resp_ts") is None:
        s_cur["resp_ts"] = time.time()
    ok = True
    try:
        if "text/event-stream" in ct:
            _handle_sse(flow, sid)
        elif _is_ndjson_ct(ct):
            # NDJSON 必须先判：application/x-ndjson 里含 "json"，落到下面的分支会
            # json.loads 整段失败 → 整条响应未还原透传（Ollama 流式实测如此）。
            _handle_ndjson(flow, sid)
        elif "json" in ct:
            _handle_json(flow, sid)
    except Exception as e:
        ok = False
        s_err = sessions.get(sid, {}) if sid else {}
        _emit("ERR", host=host, method=method, path=emit_path.split("?")[0], sid=sid, msg=str(e)[:200],
              upstream=s_err.get("upstream_name") or flow.metadata.get("shield_upstream") or "",
              model=s_err.get("model") or flow.metadata.get("shield_model") or "",
              **source)
    if ok and DEBUG:
        _debug(f"RESPONSE {host}{path.split('?')[0]} -- 还原后(返回客户端)", sid,
               flow.response.content.decode("utf-8", errors="replace"))
    if ok:
        _emit_restore_summary(flow, sid, host, method, emit_path.split("?")[0], source, ok=True)
    # 2.0 审计：restore 完成后只读扫描，不影响 body
    _audit_response(flow, sid, host, method, emit_path.split("?")[0], source)
    # 响应侧扫描：检测模型回复中不在本会话映射里的 PII（幻觉/训练数据泄漏），只记录不阻断
    _scan_response(flow, sid, host, method, emit_path.split("?")[0], source)
    _drop(sid)



def _scan_response(flow, sid, host, method, path, source, streamed_text=None):
    """响应侧扫描：还原后的 body 里出现本会话未脱敏过的 PII = 模型自己生成的（幻觉/训练数据泄漏）。

    只读不改 body，异常静默，仅在 RESPONSE_SCAN 开启时执行。
    """
    if not RESPONSE_SCAN:
        return
    try:
        resp = flow.response
        if resp is None:
            return
        s = sessions.get(sid) or {}
        fwd = s.get("fwd", {})
        restored_origs = s.get("restored_origs") or set()
        now = time.time()
        recent_ttl = _recent_ttl()

        def _is_known_orig(val):
            if val in fwd or val in restored_origs:
                return True
            rec = _RECENT_FWD.get(val)
            if rec and (now - rec[2] <= recent_ttl):
                return True
            return False

        # 流式接管时 flow.response.content 不可用，用回调累积文本
        if streamed_text is not None:
            body = streamed_text
        elif resp.content:
            body = resp.content.decode("utf-8", errors="replace")
        else:
            return
        # 响应 JSON 可能带 \uXXXX 转义（部分 SDK 默认 ensure_ascii）：直接扫原文时，
        # 转义序列的十六进制尾巴（如 \u8bdd 末位 d）会粘住数字边界导致漏检。
        # 先解析重排为非转义文本再扫（解析失败保持原文，SSE 场景走这里）。
        try:
            parsed = json.loads(body)
            if isinstance(parsed, (dict, list)):
                body = json.dumps(parsed, ensure_ascii=False)
        except Exception:
            pass
        # 超长 body 全量正则扫描会霸占事件循环（几 MB 文本 × N 条规则）：只扫前段。
        # 响应侧扫描是防御性功能，前段命中已覆盖大部分幻觉/泄漏场景，代价是可控的。
        if len(body) > _SCAN_BODY_MAX:
            body = body[:_SCAN_BODY_MAX]
        found = {}
        # 与 mask() 同款避让：被豁免的连接串区间不许 EMAIL 规则二次命中，
        # 否则模型复述的模板会被误报成「发现邮箱」（此处只影响告警，不改文本）。
        exempt_conn = []
        for rx, label, gidx in RULES:
            if not _rule_enabled(label):
                continue
            if not _rule_may_hit(body, label):
                continue  # 特征预检：不含必含特征，跳过整条规则扫描（与脱敏路径同款）
            for m in rx.finditer(body):
                orig = m.group(gidx)
                if label == "CARD" and not _card_ok(orig):
                    continue
                if label == "IDCARD" and not _idcard_ok(orig):
                    continue
                if label == "PHONE" and not _phone_ok(orig):
                    continue
                if label == "LANDLINE" and not _landline_ok(orig):
                    continue
                if label == "EMAIL" and not _email_ok(orig):
                    continue
                if label == "IBAN" and not _iban_ok(orig):
                    continue
                if label == "JWT" and not _jwt_ok(orig):
                    continue
                if label == "IP_PUBLIC" and not _ip_public_ok(orig):
                    continue
                if label == "IPV6_PRIVATE" and not _ipv6_private_ok(orig):
                    continue
                if label == "USCC" and not _uscc_ok(orig):
                    continue
                if label == "CONNSTR" and not _connstr_ok(orig, m, body):
                    if len(exempt_conn) < _CONNSTR_EXEMPT_MAX:
                        exempt_conn.append((m.start(), m.end()))
                    continue
                if label == "EMAIL" and _overlaps_exempt_conn(m.start(), m.end(), exempt_conn):
                    continue
                if _is_known_orig(orig):
                    continue  # 本会话/跨轮次脱敏或本次还原回来的值，跳过
                found.setdefault(label, {})[orig] = None
        # 用户配置的前缀规则（sk-/ah- 等）不在 RULES 里，响应侧同样要扫
        if _rule_enabled("API_KEY"):
            prefix_rx = _prefix_secret_regex()
            if prefix_rx:
                for m in prefix_rx.finditer(body):
                    orig = m.group()
                    if _is_known_orig(orig):
                        continue
                    found.setdefault("API_KEY", {})[orig] = None
        if found:
            items = []
            # found[label] 用 dict 当有序集合去重：曾用 list 直接 append 每次命中，
            # 同一个手机号在长回复里出现上万次就攒上万个重复项，SCAN_WARN 的
            # count 与明细全是同一个值刷屏（「发现 10 项」实为 1 个值重复 10 次），
            # 且白白占内存。去重后 count 才是「发现几个不同的 PII」。
            for label, vals in found.items():
                for v in list(vals)[:10]:
                    # 凭据类响应 PII 同样不明文落库（与 MASK 口径一致）
                    if label in CREDENTIAL_LABELS:
                        items.append({"label": label, "cred": True,
                                      "digest": _cred_digest(v),
                                      "preview": _preview(v, label),
                                      "length": len(v)})
                    else:
                        items.append({"label": label, "original": v, "preview": _preview(v, label)})
            s_scan = sessions.get(sid, {}) if sid else {}
            up_name = s_scan.get("upstream_name") or (flow.metadata.get("shield_upstream") if hasattr(flow, "metadata") else "") or ""
            model_name = s_scan.get("model") or (flow.metadata.get("shield_model") if hasattr(flow, "metadata") else "") or ""
            _emit("SCAN_WARN", host=host, method=method, path=path, sid=sid, count=len(items), items=items[:10],
                  upstream=up_name, model=model_name, **source)
    except Exception as e:
        s_scan = sessions.get(sid, {}) if sid else {}
        _emit("ERR", host=host, method=method, path=path, sid=sid, msg="scan:" + str(e)[:120],
              upstream=s_scan.get("upstream_name", ""), model=s_scan.get("model", ""), **source)


def _setter(obj, key):
    def _set(value):
        obj[key] = value
    return _set


def _sse_choice_index(choice, position):
    index = choice.get("index")
    return index if type(index) is int and index >= 0 else position


def _sse_response_channel(data, kind):
    """Responses API 的通道键：同一 output item 的多个 content part 必须分开。

    规范允许一个 message item 的 `content` 是数组（多个 output_text part），
    delta / .done 事件都带 `content_index`。只按 output_index 建通道会让同一 item
    下所有 part 共用一个跨 chunk 缓冲，实测两个后果：
      - part 0 的 `.done` 会 flush/pop 掉整个 item 的通道，part 1 的半截占位符
        被当成 part 0 的尾巴吐出、或被直接丢掉；
      - 两个 part 的增量交错时，半截占位符会串到另一个 part 的文本里。

    `content_index` 缺失或为 0 时**省略该段**，键形与改动前完全一致
    （`r0.text`）—— 官方目前每个 message 只发一个 part，存量单 part 流的行为
    零变化。这个改动只影响真的下发多 part 的自建/中转实现。

    刻意**不引入 item_id**：它在部分中转实现里会缺失，一旦 delta 与 .done 的
    item_id 不齐，就会让「.done 清理该通道」失配（缓冲残留被重复吐出），比只用
    output_index 更糟；而 output_index 已足以区分不同 item。
    """
    ci = data.get("content_index")
    if type(ci) is int and ci > 0:
        return "r%s.%d.%s" % (data.get("output_index", 0), ci, kind)
    return "r%s.%s" % (data.get("output_index", 0), kind)


def _sse_text_slots(data):
    """列出 SSE 事件里的增量文本槽位：[(channel, text, setter, escape)]。

    只有"增量"字段才需要跨 chunk 缓冲半截占位符，且每个字段必须用独立通道 ——
    正文 delta 与 tool 参数 delta 共用缓冲会把上一个字段的尾巴吐进下一个字段，
    表现为字段被清空、内容错位。
    """
    slots = []
    if not isinstance(data, dict):
        return slots
    # OpenAI Chat Completions / Completions 流
    for position, c in enumerate(data.get("choices", []) or []):
        if not isinstance(c, dict):
            continue
        # Sparse chunks may each contain only one of several completion choices.
        idx = _sse_choice_index(c, position)
        d = c.get("delta")
        if isinstance(d, dict):
            if isinstance(d.get("content"), str):
                slots.append((f"c{idx}.content", d["content"], _setter(d, "content"), False))
            if isinstance(d.get("reasoning_content"), str):
                slots.append((f"c{idx}.reason", d["reasoning_content"], _setter(d, "reasoning_content"), False))
            # 部分上游同时下发 reasoning_content 与 reasoning 两份同内容
            # 增量，各自独立切分——必须单独槽位独立缓冲，否则半截占位符原样透传
            # （探针实测：{{TESTNAME 残片直接出现在 SSE 里），且与 reason 通道共用
            # 会把两份文本互相串字。
            if isinstance(d.get("reasoning"), str):
                slots.append((f"c{idx}.reason2", d["reasoning"], _setter(d, "reasoning"), False))
            for tidx, tc in enumerate(d.get("tool_calls", []) or []):
                fn = tc.get("function") if isinstance(tc, dict) else None
                # 槽位键必须用 tool_calls[].index（协议里标明这段增量属于第几个工具），
                # 不能用数组下标：并行工具调用时每个 chunk 通常只带一个元素，
                # index=0 和 index=1 的增量都会拿到下标 0，两个工具的跨包缓冲直接串在
                # 一起——表现为参数互相污染、JSON 解析失败（SHIELD-TOOLIDX-001）。
                # index 缺失时才回落数组下标（少数上游不下发该字段）。
                slot_no = tc.get("index") if isinstance(tc, dict) and isinstance(tc.get("index"), int) else tidx
                # arguments 是 JSON 文本，还原值要按 JSON 转义，否则客户端解析工具参数直接报错
                if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
                    slots.append((f"c{idx}.tool{slot_no}", fn["arguments"], _setter(fn, "arguments"), True))
            # 旧式 function_call（OpenAI 2023 协议，部分中转与本地推理框架仍在用）：
            # 参数同样按增量下发，没有槽位就完全不还原，客户端拿占位符去执行工具。
            fc = d.get("function_call")
            if isinstance(fc, dict) and isinstance(fc.get("arguments"), str):
                slots.append((f"c{idx}.fcall", fc["arguments"], _setter(fc, "arguments"), True))
        if isinstance(c.get("text"), str):
            slots.append((f"c{idx}.text", c["text"], _setter(c, "text"), False))
    etype = data.get("type") if isinstance(data.get("type"), str) else ""
    # Anthropic Messages 流
    if etype == "content_block_delta":
        d = data.get("delta")
        if isinstance(d, dict):
            blk = data.get("index", 0)
            if isinstance(d.get("text"), str):
                slots.append((f"a{blk}.text", d["text"], _setter(d, "text"), False))
            if isinstance(d.get("thinking"), str):
                slots.append((f"a{blk}.think", d["thinking"], _setter(d, "thinking"), False))
            # tool_use 参数按 partial_json 增量下发，不还原客户端就拿占位符去执行工具
            if isinstance(d.get("partial_json"), str):
                slots.append((f"a{blk}.pj", d["partial_json"], _setter(d, "partial_json"), True))
    # OpenAI Responses API 流
    if etype == "response.output_text.delta" and isinstance(data.get("delta"), str):
        slots.append((_sse_response_channel(data, "text"), data["delta"], _setter(data, "delta"), False))
    elif etype == "response.reasoning_text.delta" and isinstance(data.get("delta"), str):
        # 思考文本独立通道（同 reasoning_content：跨 chunk 半截占位符必须缓冲还原，
        # 曾漏槽位导致 {{ 残片透传；与正文通道分开避免串字）
        slots.append((_sse_response_channel(data, "reason"), data["delta"], _setter(data, "delta"), False))
    elif etype == "response.function_call_arguments.delta" and isinstance(data.get("delta"), str):
        slots.append((_sse_response_channel(data, "args"), data["delta"], _setter(data, "delta"), True))
    # Ollama NDJSON 增量。用 "done" 做判别（Ollama 每条记录都带它），避免把
    # OpenAI 非流式响应里的 choices[].message 误当增量槽位。
    if "done" in data:
        msg = data.get("message")
        if isinstance(msg, dict) and isinstance(msg.get("content"), str):
            slots.append(("o.message.content", msg["content"], _setter(msg, "content"), False))
        # /api/generate 的正文直接放在顶层 response 字段
        if isinstance(data.get("response"), str):
            slots.append(("o.response", data["response"], _setter(data, "response"), False))
    return slots


def _sse_terminal_prefixes(data):
    """Channels ending in this event: None means all, () means none."""
    if not isinstance(data, dict):
        return ()
    if data.get("type") in ("message_stop", "message_delta", "response.completed",
                            "response.incomplete", "response.failed"):
        return None
    if data.get("type") == "content_block_stop":
        return (f"a{data.get('index', 0)}.",)
    # 收尾通道必须与 _sse_text_slots 的通道键同源（含 content_index），否则
    # part 0 的 .done 会把 part 1 的缓冲一起冲掉。
    if data.get("type") == "response.output_text.done":
        return (_sse_response_channel(data, "text"),)
    if data.get("type") == "response.reasoning_text.done":
        return (_sse_response_channel(data, "reason"),)
    if data.get("type") == "response.function_call_arguments.done":
        return (_sse_response_channel(data, "args"),)
    return tuple(f"c{_sse_choice_index(c, position)}."
                 for position, c in enumerate(data.get("choices", []) or [])
                 if isinstance(c, dict) and c.get("finish_reason"))


def _restore_sse_data(data, sid, final=False, final_prefixes=()):
    """就地还原单个 SSE 事件的 JSON 负载。非 dict 负载（null/[]/"x"/123）直接原样返回。"""
    if not isinstance(data, dict):
        return data
    slots = _sse_text_slots(data)
    if slots:
        s = sessions.get(sid) or {}
        for channel, text, setter, escape in slots:
            channel_final = final or final_prefixes is None or channel.startswith(final_prefixes)
            setter(restore(text, sid, channel=channel, escape=escape, final=channel_final))
        # 只有真的留下半截占位符时才记模板（收尾补发用），正常路径零额外序列化
        pend = s.get("pending") or {}
        for channel, _t, _s, escape in slots:
            if pend.get(channel):
                s.setdefault("flush_tmpl", {})[channel] = json.dumps(data, ensure_ascii=False)
        return
    # 非增量事件（message_start / content_block_start / response.completed …）是完整快照，整树还原
    for k, v in list(data.items()):
        data[k] = _restore_tree(v, sid, k)
    # Responses .done payloads replace the full value, rather than extending
    # its deltas. Discard that channel's stale tail after restoring the snapshot;
    # appending it would duplicate text or emit a delta after completion.
    snapshot = {
        "response.output_text.done": ("text", "text"),
        "response.reasoning_text.done": ("text", "reason"),
        "response.function_call_arguments.done": ("arguments", "args"),
    }.get(data.get("type"))
    if snapshot is not None and isinstance(data.get(snapshot[0]), str):
        channel = _sse_response_channel(data, snapshot[1])
        s = sessions.get(sid) or {}
        s.get("pending", {}).pop(channel, None)
        s.get("flush_tmpl", {}).pop(channel, None)


def _build_flush_event(tmpl_json, channel, leftover):
    """用最后一个同通道事件做模板，补发一条只含残留文本的事件。

    直接把残留文本裸拼在流末尾会破坏 SSE 结构，克隆真实事件才能保证
    客户端 SDK 的字段校验（id/model/created 等）通过。
    """
    try:
        data = json.loads(tmpl_json)
    except Exception:
        return ""
    hit = False
    for ch, _text, setter, escape in _sse_text_slots(data):
        if ch == channel:
            setter(leftover)
            hit = True
        else:
            setter("")  # 其余槽位清空，避免重复下发同一段文本
    if not hit and channel.endswith(":db") and isinstance(data, dict):
        # 支持扩展豆包等私有信封模板回填，避免异常截断时收尾退化为裸文本
        cnt = data.get("content")
        if isinstance(cnt, str) and cnt.startswith("{") and "text" in cnt:
            try:
                inner = json.loads(cnt)
                if isinstance(inner, dict) and "text" in inner:
                    inner["text"] = leftover
                    data["content"] = json.dumps(inner, ensure_ascii=False)
                    hit = True
            except Exception:
                pass
        elif isinstance(cnt, dict) and "text" in cnt:
            cnt["text"] = leftover
            hit = True
    if not hit:
        return ""
    for c in data.get("choices", []) or []:
        if isinstance(c, dict):
            c["finish_reason"] = None  # 补发事件不能带结束标记
    prefix = ""
    if isinstance(data.get("type"), str):
        prefix = "event: %s\n" % data["type"]  # Anthropic / Responses 客户端依赖 event: 行
    return prefix + "data: " + json.dumps(data, ensure_ascii=False) + "\n\n"


def _wrap_bare_flush(text, framing):
    """无模板可克隆时的**最小合法外壳**（兜底，只为不丢字）。

    SSE：每行都要带 `data: ` 前缀，内部的换行必须拆成多条 data 行——直接拼裸文本
    会被符合规范的解析器丢掉。NDJSON：必须是一行合法 JSON，用 {"content": ...} 承接。
    两种外壳都不引入新语义，客户端读不到就忽略，但不会让补发的字连同整行一起消失。
    """
    if not text:
        return ""
    try:
        if framing == "ndjson":
            return json.dumps({"content": text}, ensure_ascii=False) + "\n"
        return "\n".join("data: " + ln for ln in str(text).split("\n")) + "\n\n"
    except Exception:
        return ""


def _flush_pending(sid, channel_prefixes=None, framing="sse"):
    """把各通道滞留的半截占位符补发出去，返回待追加的流文本。

    补发前必须先把 leftover 还原成原文（final=True 清空通道缓冲），
    否则客户端收到的补发帧里是未还原的占位符。
    framing 决定补发帧的封装形态：SSE 要克隆完整事件（客户端 SDK 会校验字段），
    NDJSON 只要一行 JSON。
    """
    s = sessions.get(sid)
    if not s:
        return ""
    pend = s.get("pending")
    if not isinstance(pend, dict) or not pend:
        return ""
    tmpl = s.get("flush_tmpl") or {}
    out = []
    for channel, leftover in list(pend.items()):
        if channel_prefixes is not None and not channel.startswith(channel_prefixes):
            continue
        pend.pop(channel, None)  # 先取出，避免 restore 内部把自身 pending 再拼一遍
        tmpl_json = tmpl.pop(channel, "")
        if not leftover:
            continue
        try:
            slots = _sse_text_slots(json.loads(tmpl_json)) if tmpl_json else []
            escape = next((slot[3] for slot in slots if slot[0] == channel), False)
            restored = restore(leftover, sid, channel=channel, escape=escape, final=True)
        except Exception:
            restored = leftover
        builder = _build_flush_line if framing == "ndjson" else _build_flush_event
        evt = builder(tmpl_json, channel, restored)
        if evt:
            out.append(evt)
        elif restored:
            # 没有可用模板时**不能裸拼文本**：SSE 里裸文本没有 `data:` 前缀，严格解析器
            # 整行忽略；NDJSON 里裸文本不是合法 JSON，整行同样被丢弃。两条路径都会把
            # 补发内容吃掉（channel="raw" 的非 JSON 载荷走的正是这条无模板路径）。
            out.append(_wrap_bare_flush(restored, framing))
    return "".join(out)


def _build_flush_line(tmpl_json, channel, leftover):
    """NDJSON 版的收尾补发：克隆最后一条同通道记录，只留残留文本。"""
    try:
        data = json.loads(tmpl_json)
    except Exception:
        return ""
    if not isinstance(data, dict):
        return ""
    hit = False
    for ch, _text, setter, _escape in _sse_text_slots(data):
        if ch == channel:
            setter(leftover)
            hit = True
        else:
            setter("")  # 其余槽位清空，避免重复下发同一段文本
    if not hit:
        return ""
    if "done" in data:
        data["done"] = False  # 补发帧不能带结束标记
    return json.dumps(data, ensure_ascii=False) + "\n"


def _restore_ndjson_line(line, sid, final=False):
    """还原 NDJSON 流中的单行 JSON（Ollama /api/chat 等）。

    整包 `json.loads` 对 NDJSON 必然失败，此前这条路径整个退化成「未还原透传」——
    用户在自己的客户端里看到 `{{PHONE_ab12cd}}` 原样留在回复中，而面板显示一切正常。

    与 SSE 同构：增量文本槽位走通道缓冲（半截占位符不原样透传），其余字段整树还原。
    解析失败的行原样返回：一行坏不能把整段输出吃掉。
    """
    stripped = line.strip()
    if not stripped:
        return line
    try:
        obj = json.loads(stripped)
    except Exception:
        # 调用方已保证只在「整行到齐」时进来（流式路径按 \n 切帧），
        # 走到这里说明上游本来就发了非 JSON 的行，吞掉它只会让客户端缺数据。
        return line
    if not isinstance(obj, dict):
        return line
    try:
        slots = _sse_text_slots(obj)
        if slots:
            s = sessions.get(sid) or {}
            for channel, text, setter, escape in slots:
                setter(restore(text, sid, channel=channel, escape=escape, final=final))
            # 只有真的留下半截占位符时才记模板（收尾补发用），正常路径零额外序列化
            pend = s.get("pending") or {}
            for channel, _t, _s2, _e in slots:
                if pend.get(channel):
                    s.setdefault("flush_tmpl", {})[channel] = json.dumps(obj, ensure_ascii=False)
            return json.dumps(obj, ensure_ascii=False)
        return json.dumps(_restore_tree(obj, sid), ensure_ascii=False)
    except Exception:
        return line


# NDJSON（换行分隔 JSON）内容类型。Ollama 用 application/x-ndjson，
# 部分网关用 application/jsonl / application/x-jsonlines。
_NDJSON_CONTENT_TYPES = ("application/x-ndjson", "application/ndjson",
                         "application/jsonl", "application/x-jsonlines")


def _is_ndjson_ct(content_type):
    ct = (content_type or "").lower()
    return any(t in ct for t in _NDJSON_CONTENT_TYPES)


def _handle_ndjson(flow, sid):
    """整包 NDJSON 还原（流式接管关闭或未触发时的回退路径）。"""
    raw = flow.response.content.decode("utf-8", errors="replace")
    lines = raw.split("\n")
    last = len(lines) - 1
    out = []
    for i, line in enumerate(lines):
        out.append(_restore_ndjson_line(line, sid, final=(i == last)))
    # 与 _handle_sse 对齐补收尾：最后一行以半截占位符结尾（模型被 max_tokens 截断在
    # 占位符中间）时，通道缓冲里的碎片不补发就被静默丢弃——回复少几个字，
    # 而 RESTORE 事件显示一切正常。
    tail = _flush_pending(sid, framing="ndjson")
    if tail:
        out.append(tail.rstrip("\n"))
    flow.response.content = "\n".join(out).encode("utf-8")


def _restore_sse_event(block, sid, final=False):
    """还原一个 SSE 事件块（可能含多行）。返回还原后的文本块。

    按事件粒度处理是流式透传的前提：一个事件到手立刻还原、立刻下发，
    首字延迟才不会等于整段生成时长。
    """
    out_lines = []
    for line in block.split("\n"):
        stripped = line.rstrip("\r")
        # 兼容 `data:`（无空格）与 `data: ` 两种 SSE 写法
        if stripped.startswith("data:"):
            payload = stripped[5:].lstrip(" ")
            if payload.strip() == "[DONE]":
                tail = _flush_pending(sid)  # [DONE] 之前必须把缓冲吐净，客户端见到 DONE 就不再收了
                if tail:
                    # tail 是完整 SSE 事件块（自带 \n\n），作为独立段插入，
                    # 前后必须有空行分隔，否则与相邻 data 行粘连成一个事件
                    out_lines.append("")
                    out_lines.extend(tail.rstrip("\n").split("\n"))
                    out_lines.append("")
                out_lines.append(line)
                continue
            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                out_lines.append("data: " + restore(payload, sid, channel="raw", final=final))
                continue
            # 合法 JSON 但**不是对象**（null / [] / "x" / 123）：下面一律按 dict 用
            # （.get() / .items()），以前会抛 AttributeError，被 _handle_response 的
            # 外层 except 吞成一条 ERR 事件 —— 整条响应就此退化成「未还原透传」，
            # 用户看到的是占位符原样留在回复里。这类负载没有可还原的槽位，原样透传即可。
            if not isinstance(data, dict):
                out_lines.append(line)
                continue
            ending = _sse_terminal_prefixes(data)
            # A terminal chunk can contain the final text fragment. Restore it
            # before flushing, and leave other choices' partial tokens buffered.
            _restore_sse_data(data, sid, final=final, final_prefixes=ending)
            if ending is None or ending:
                tail = _flush_pending(sid, channel_prefixes=ending)
                if tail:
                    out_lines.append("")
                    out_lines.extend(tail.rstrip("\n").split("\n"))
                    out_lines.append("")
            out_lines.append("data: " + json.dumps(data, ensure_ascii=False))
            continue
        out_lines.append(line)
    return "\n".join(out_lines)


def _restore_ext_sse_event(block, sid, stream_id, final=False):
    """扩展链路专属 SSE 事件还原。优先解耦处理豆包等私有信封，其余走标准 SSE 管线。

    块内**逐行独立判定**：SSE 规范允许一个事件块里有多条 data: 行，而豆包信封与
    标准 OpenAI 行完全可能同块并存。旧实现一见豆包行就整块 early return，同块其余
    的 data: 行既不还原、也不再交给 `_restore_sse_event` —— 占位符原样漏到页面上，
    这是浏览器链路唯一的泄漏形态且极难复现（要上游正好把两种行合进同一个事件块）。
    未命中豆包信封的行按**连续段**交回标准管线，保住多行事件的原有语义。
    """
    out_lines = []
    rest = []          # 连续的非豆包行，攒成一段后整体走标准管线

    def flush_rest():
        if not rest:
            return
        out_lines.extend(_restore_sse_event("\n".join(rest), sid, final=final).split("\n"))
        rest.clear()

    for line in block.split("\n"):
        stripped = line.rstrip("\r")
        if stripped.startswith("data:"):
            payload = stripped[5:].lstrip(" ")
            if payload.strip() and payload.strip() != "[DONE]":
                try:
                    data = json.loads(payload)
                except Exception:
                    data = None
                if isinstance(data, dict) and "choices" not in data and "response" not in data:
                    cnt = data.get("content")
                    channel = f"ext:{stream_id}:db"
                    replaced = None
                    if isinstance(cnt, str) and cnt.startswith("{") and "text" in cnt:
                        try:
                            inner = json.loads(cnt)
                        except Exception:
                            inner = None
                        if isinstance(inner, dict) and isinstance(inner.get("text"), str):
                            inner["text"] = restore(inner["text"], sid, channel=channel,
                                                    escape=False, final=final)
                            data["content"] = json.dumps(inner, ensure_ascii=False)
                            replaced = data
                    elif isinstance(cnt, dict) and isinstance(cnt.get("text"), str):
                        cnt["text"] = restore(cnt["text"], sid, channel=channel,
                                              escape=False, final=final)
                        replaced = data
                    if replaced is not None:
                        flush_rest()
                        out_lines.append("data: " + json.dumps(replaced, ensure_ascii=False))
                        s_ = sessions.get(sid) or {}
                        pend = s_.get("pending") or {}
                        if pend.get(channel):
                            s_.setdefault("flush_tmpl", {})[channel] = json.dumps(replaced, ensure_ascii=False)
                        continue
        rest.append(line)
    flush_rest()
    return "\n".join(out_lines)


def restore_stream_chunk(text, sid, stream_id, content_type="", escape=False, final=False):
    """扩展链路的**分帧**还原入口：按帧边界切开流文本，逐帧走与代理链路相同的管线。

    ── 为什么必须有这一层（2026-09-16 真机往返实测定位）──

    代理链路是**引擎自己解析 SSE**：`_sse_stream_factory` 按空行切事件 →
    `json.loads` 取出负载 → `_sse_text_slots` 抽出**增量文本槽位** → 把**槽位文本**
    交给 `restore()`。于是半截占位符天然落在缓冲区结尾，`_PARTIAL_RX` 的
    「半截正好在结尾」判据成立，跨事件拼接正常。

    扩展链路此前把**整段 SSE 原文**（含 `data: {...}` 外壳）直接喂给 `restore()`。
    模型逐 token 输出时占位符会被切成两个事件：

        event A  content = "{{EMAIL"
        event B  content = "_dsszcd}}"

    `restore()` 看到的缓冲区结尾是 `"}}]}\\n\\n` 而不是半截占位符，判据永不成立 →
    两半各自原样下发，页面上留下裸 `{{EMAIL_dsszcd}}`。实测 Qwen 真实往返即此现象，
    且引擎侧 RESTORE 事件是 `restored=0 unresolved=0`——因为 `{{{` 从没进过替换阶段。

    修法**不是**放宽 `restore()` 的半截判据：那是代理链路共用的核心，改它等于让
    两条链路的缓冲行为互相牵扯。正确做法是把扩展链路提升到与代理链路**同一粒度**，
    由引擎做分帧 + 槽位抽取。副作用是扩展链路顺带继承了代理链路的全部能力：

    - 每个槽位独立通道，正文 / reasoning / tool_calls.arguments 互不串字；
    - 按槽位判定 escape（工具参数需 JSON 转义、正文不需要），不再靠"整条流猜一个值"；
    - 终止事件与 `[DONE]` 前后的缓冲补发（`_flush_pending`），不吞最后几个字。

    `stream_id` 用于在当前会话中隔离半帧切片缓冲 `ext_frames[stream_id]`。
    当前扩展链路每次 mask 均签发唯一的独立 sid，单 sid 对应单条流；通道状态由 sid 隔离。
    """
    s = sessions.get(sid)
    if not s or not isinstance(text, str):
        return text
    frames = s.get("ext_frames")
    if not isinstance(frames, dict):
        frames = s["ext_frames"] = {}
    elif stream_id not in frames and len(frames) >= _EXT_FRAMES_MAX:
        # stream_id 由页面可控（审计 M2）：不设上限就能在会话 TTL 内把引擎内存撑大。
        # dict 保持插入序，淘汰最老的一条即可。
        frames.pop(next(iter(frames)), None)

    ct = (content_type or "").lower()
    if _is_ndjson_ct(ct):
        kind, sep = "ndjson", "\n"
    elif "text/event-stream" in ct:
        kind, sep = "sse", "\n\n"
    else:
        # 非流式整体：JSON 响应体里的占位符都落在字符串内部，必须按 JSON 转义。
        # 其它类型（text/plain 等）沿用调用方判定。
        # 透传 final 参数：扩展对大响应的每个 TCP chunk 都会调用本函数（final=False），
        # 只有在 flush 阶段才会发 final=True。若写死 final=True，跨分片的占位符
        # 会在第一片就被提前清空缓冲，导致第二片拼不回。
        if final:
            frames.pop(stream_id, None)
        return restore(text, sid, channel=f"ext:{stream_id}",
                       escape=("json" in ct) or escape, final=final)

    # SSE 允许 CRLF；统一成 LF 后再按空行切事件（与 _sse_stream_factory 同源）
    buf = (frames.get(stream_id, "") + text).replace("\r\n", "\n")
    out = []
    # 只处理**已完整到达**的帧，半帧留在缓冲里等下一次调用——
    # 这正是「占位符被切在两个事件之间」能拼回来的原因。
    while True:
        idx = buf.find(sep)
        if idx < 0:
            break
        block, buf = buf[:idx], buf[idx + len(sep):]
        if kind == "sse":
            out.append(_restore_ext_sse_event(block, sid, stream_id, final=False) + sep)
        else:
            out.append(_restore_ndjson_line(block, sid, final=False) + sep)
    # 异常上游防御：持续推送不含帧边界的数据会让缓冲无限增长（内存 + 首字延迟失控）。
    # 与代理链路同样优先在最后一个换行处切分，避免把合法 JSON 拦腰截断。
    if len(buf) > _SSE_BUF_MAX:
        if kind == "sse":
            idx = buf.rfind("\n")
            if idx >= 0:
                out.append(_restore_ext_sse_event(buf[:idx], sid, stream_id, final=True) + sep)
                buf = buf[idx + 1:]
            else:
                out.append(_restore_ext_sse_event(buf, sid, stream_id, final=True) + sep)
                buf = ""
        else:
            out.append(_restore_ndjson_line(buf, sid, final=True) + sep)
            buf = ""
    if final:
        if buf:
            out.append(_restore_ext_sse_event(buf, sid, stream_id, final=True) if kind == "sse"
                       else _restore_ndjson_line(buf, sid, final=True))
        tail = _flush_pending(sid, framing="ndjson") if kind == "ndjson" else _flush_pending(sid)
        if tail:
            out.append(tail)
        frames.pop(stream_id, None)
    else:
        frames[stream_id] = buf
    return "".join(out)


def _sse_stream_factory(flow, sid, host, method, emit_path, source, framing="sse"):
    """构造 mitmproxy 响应流回调：按帧边界增量还原并立即下发。

    mitmproxy 默认把响应整包收完才交给 response 钩子，流式因此完全失去效果
    （首字延迟 = 整段生成时长，长回答表现为卡死）。这里在 responseheaders 阶段
    接管流，逐块处理。

    framing 决定切帧方式：`sse`（空行分隔的事件块，OpenAI/Anthropic/Gemini alt=sse/
    Cohere v2）与 `ndjson`（换行分隔的 JSON 行，Ollama）。两种格式的占位符跨 TCP 块
    分裂问题靠同一套「只在帧完整时处理」解决。
    """
    state = {
        "decoder": codecs.getincrementaldecoder("utf-8")(errors="replace"),
        "buf": "",
        "text": [],       # 还原后文本留存（供审计/扫描），有上限
        "text_len": 0,
        "truncated": False,  # 文本留存已达上限，后续块不再累积
        "usage": {},      # 累计 token 用量，保留未再次上报的字段（与文本留存解耦）
        "done": False,
        "calls": 0,       # 诊断：stream 回调被调用次数
        "bytes_in": 0,    # 诊断：累计输入字节
    }

    def _keep(chunk):
        # usage 在流末最后几个 chunk 才出现，但文本留存有 256KB 上限：长回答
        # （实测单次 completion 达 1 万+ token）会把带 usage 的尾部整个丢掉，
        # 「今日 Token 用量」永久少计。因此 usage 每块单独扫，不受留存上限影响。
        try:
            u = _extract_usage(chunk, previous=state["usage"])
            if u:
                state["usage"] = u
        except Exception:
            pass
        if state["text_len"] < _SSE_KEEP_MAX:
            state["text"].append(chunk)
            state["text_len"] += len(chunk)
        elif not state["truncated"]:
            state["truncated"] = True

    def _finish():
        if state["done"]:
            return
        state["done"] = True
        # 关键：流式接管下绝不能设置 flow.response.content —— mitmproxy 12 会把响应
        # 标记为已改写，导致客户端收到连接重置(0 字节)。还原后的完整文本已在
        # state["text"] 里，直接传给事件/审计/扫描，不再碰 flow.response.content。
        restored_text = "".join(state["text"])
        _emit_restore_summary(flow, sid, host, method, emit_path, source, ok=True, streamed_text=restored_text, stream_actual="stream", stream_usage=state["usage"])
        _audit_response(flow, sid, host, method, emit_path, source, streamed_text=restored_text)
        _scan_response(flow, sid, host, method, emit_path, source, streamed_text=restored_text)
        _drop(sid)

    def _stream(data: bytes):
        if state["done"]:
            return data
        try:
            state["calls"] += 1
            state["bytes_in"] += len(data)
            # 计数同步到 flow.metadata：流被中途切断时 _finish() 不会执行，
            # 只有 error() 钩子能看到现场，靠这两个数区分「上游没吐完」与
            # 「我们处理到一半崩了」。
            flow.metadata["shield_stream_calls"] = state["calls"]
            flow.metadata["shield_stream_bytes"] = state["bytes_in"]
            _touch(sid)  # 长生成期间刷新会话 TTL，防止 _sweep 误删活动中的流式会话
            # 首字节计时：第一次收到非空数据块即记（含流式接管路径）
            if data:
                s_cur = sessions.get(sid)
                if s_cur is not None:
                    if s_cur.get("resp_ts") is None:
                        s_cur["resp_ts"] = time.time()
                    if s_cur.get("first_byte_ms") is None:
                        s_cur["first_byte_ms"] = (time.perf_counter() - s_cur.get("req_t0", time.perf_counter())) * 1000
            last = not data
            state["buf"] += state["decoder"].decode(data, final=last)
            # SSE 允许 CRLF；统一成 LF 后按空行切事件。此前只找 \n\n，
            # CRLF 上游会把整段响应攒到流结束，客户端可能 chunk timeout 并截断。
            state["buf"] = state["buf"].replace("\r\n", "\n")
            out = []
            if framing == "ndjson":
                # NDJSON：一行一个 JSON。只处理已带换行的完整行，半行留在缓冲里
                # （占位符被 TCP 边界切开时靠这条保证不会被当成坏 JSON 丢掉）。
                while True:
                    idx = state["buf"].find("\n")
                    if idx < 0:
                        break
                    line, state["buf"] = state["buf"][:idx], state["buf"][idx + 1:]
                    out.append(_restore_ndjson_line(line, sid, final=False) + "\n")
                # 异常上游防御：单个超长行无换行符，累积超过 _SSE_BUF_MAX 强制还原清空
                if len(state["buf"]) > _SSE_BUF_MAX:
                    out.append(_restore_ndjson_line(state["buf"], sid, final=True) + "\n")
                    state["buf"] = ""
                if last:
                    if state["buf"]:
                        out.append(_restore_ndjson_line(state["buf"], sid, final=True))
                        state["buf"] = ""
                    tail = _flush_pending(sid, framing="ndjson")
                    if tail:
                        out.append(tail)
                    _touch(sid)
            else:
                # SSE 事件以空行分隔；只处理已完整到达的事件，半个事件留在缓冲里
                while True:
                    idx = state["buf"].find("\n\n")
                    if idx < 0:
                        break
                    block, state["buf"] = state["buf"][:idx], state["buf"][idx + 2:]
                    out.append(_restore_sse_event(block, sid, final=False) + "\n\n")
                # 异常上游防御：上游持续推送只有单换行（无 \n\n 双空行）或无换行的巨型数据，
                # 导致 buf 无限累积超过 _SSE_BUF_MAX。优先在最后一个换行符切分以保留完整
                # data: 行（避免破坏合法 JSON），无换行时整段强制还原清空。
                if len(state["buf"]) > _SSE_BUF_MAX:
                    idx = state["buf"].rfind("\n")
                    if idx >= 0:
                        block, state["buf"] = state["buf"][:idx], state["buf"][idx + 1:]
                        out.append(_restore_sse_event(block, sid, final=True) + "\n\n")
                    else:
                        out.append(_restore_sse_event(state["buf"], sid, final=True) + "\n\n")
                        state["buf"] = ""
                if last:
                    if state["buf"]:
                        out.append(_restore_sse_event(state["buf"], sid, final=True))
                        state["buf"] = ""
                    # 收尾：把各通道缓冲里的残留补发出去，避免吞掉最后几个字
                    tail = _flush_pending(sid)
                    if tail:
                        out.append(tail)
                    _touch(sid)
            text = "".join(out)
            _keep(text)
            if _STREAM_DEBUG:
                # 断流归因用：能区分「上游没吐完」（回调停了但无 last）与
                # 「我们卡在半个事件里」（buf 一直非空、out 恒为空）。
                _log(f"[stream:dbg] {host} cb#{state['calls']} in={len(data)}B "
                     f"out={len(text)}B buf={len(state['buf'])} last={last}")
            if last:
                _finish()
                # 末块走 mitmproxy 的 ResponseEndOfMessage 分支，那里对 b"" 有
                # 专门过滤（chunks == b"" -> []），返回 bytes 安全。
                return text.encode("utf-8")
            # 关键：中途块绝不能返回 b""。mitmproxy 的 ResponseData 分支不过滤空块，
            # 会按 chunked 语法写出 b"0\r\n\r\n"——那正是**终止块**，客户端据此判定
            # 响应结束、停止读取并关连接（引擎侧表现为 CANCEL Client disconnected）。
            # SSE 事件被上游按 TCP 边界切成两段时（半个事件留在 buf 里，本次无完整
            # 事件可发）必然触发，能否复现只取决于分片运气，与上游是否支持流式无关。
            # 返回空列表则 mitmproxy 的 for 循环零次迭代，一个字节都不写，流保持打开。
            if not text:
                return []
            return text.encode("utf-8")
        except Exception as e:
            # 流式处理失败：放弃改写，原样透传剩余数据，绝不把连接搞断。
            # 缓冲里已解码但未输出的部分必须拼回去，否则客户端收到缺块的半截流。
            state["done"] = True
            s_sse = sessions.get(sid, {}) if sid else {}
            _emit("ERR", host=host, method=method, path=emit_path, sid=sid, msg=f"{framing}_stream:" + str(e)[:160],
                  upstream=s_sse.get("upstream_name", ""), model=s_sse.get("model", ""), **source)
            try:
                buf = state.get("buf") or ""
                state["buf"] = ""
                # 异常时 buf 是已解码但未还原的 SSE 残片（含占位符/半截占位符）：
                # 先做最后一次还原再下发，把残片泄漏面压到最小。正常路径的还原
                # 在 _restore_sse_event 流末 final=True 已完成，这里仅兜底异常分支。
                try:
                    restored_buf = restore(buf, sid, final=True)
                except Exception:
                    # 还原与流式处理同一异常源（会话结构损坏等）：回退原始 buf，
                    # 宁可透传占位符也绝不丢数据（占位符不含明文，fail-safe 方向）。
                    restored_buf = buf
                # 通道级残留也必须吐出去。restore(..., final=True) 的 channel 默认是
                # ""，只清得掉那一个槽；正文/思考/工具参数通道（c0.content / a0.think /
                # r0.args …）里被扣住的半截占位符会被静默丢弃 —— 与上面「已解码但未
                # 输出的部分必须拼回去」的意图相悖，客户端会看到文本凭空少一截。
                # 顺序与正常流末（_stream 的 last 分支）一致：先 buf（事件级残片）
                # 再 pending（更早的通道滞留，此时已被上面那次 restore 顺带清掉同通道）。
                try:
                    flush_txt = _flush_pending(sid)
                except Exception:
                    flush_txt = ""
                # 补发的是完整 SSE 事件块（自带 \n\n），前面必须另起一行：否则会与
                # 残片粘成同一行 `data: {…}data: {…}`，严格按行解析的 SDK 直接
                # JSON.parse 失败并丢掉整条补发事件（等于白补）。
                sep = "\n\n" if restored_buf and not restored_buf.endswith("\n\n") else ""
                passthrough = (restored_buf + sep + flush_txt).encode("utf-8", errors="replace") + data
            except Exception:
                passthrough = data
            # 必须补发 RESTORE：只发 ERR 会让该请求在日志里只有 MASK 没有还原记录，
            # 「已还原回复」统计永久少一条，用户无从判断这次到底还原没有。
            # ok=False + 已还原文本一并带上，success/unresolved 如实反映失败态。
            try:
                _emit_restore_summary(
                    flow, sid, host, method, emit_path, source,
                    ok=False, streamed_text="".join(state["text"]), stream_actual="stream_error",
                    stream_usage=state["usage"],
                )
            except Exception:
                pass
            try:
                _drop(sid)
            except Exception:
                pass
            # 这里无需防空返回：passthrough = 残留 + data，data 非空则必非空；
            # data 为空即末块，走 mitmproxy 的 EndOfMessage 分支（对 b"" 有过滤）。
            return passthrough

    return _stream


def _emit_restore_summary(flow, sid, host, method, path, source, ok=True, streamed_text=None, stream_actual="whole", stream_usage=None):
    """记录 RESTORE 事件（流式与非流式共用）。

    stream_actual 表示引擎实际处理方式（区别于客户端请求类型 stream_mode）：
    - "stream"：responseheaders 流式接管，逐事件下发
    - "whole"：整包还原后一次性下发（黑名单上游 / stream_response 关闭 / 非 SSE）
    """
    s = sessions.get(sid, {})
    masked_count = len(s.get("fwd", {}))
    restored_count = int(s.get("restored", 0) or 0)
    restored_unique = len(s.get("restored_tokens", set()) or set())
    unresolved = int(s.get("unresolved", 0) or 0)
    degraded = int(s.get("degraded", 0) or 0)
    if masked_count == 0:
        restore_status = "no_sensitive_data"
    elif unresolved > 0:
        # 有占位符查不到原文（复用表淘汰/会话被扫/孤儿占位符）：告警态，前端要能看到
        restore_status = "unresolved"
    elif restored_count > 0:
        restore_status = "restored"
    else:
        restore_status = "no_placeholder_in_response"
    resp_preview = ""
    resp_dialog = ""
    try:
        # 流式接管时用回调累积的文本；非流式读 flow.response.content
        if streamed_text is not None:
            resp_preview = _body_preview(streamed_text.encode("utf-8"), 800)
            resp_dialog = _extract_chat_dialog(streamed_text.encode("utf-8"), 4000)
        elif flow.response and flow.response.content:
            resp_preview = _body_preview(flow.response.content, 800)
            resp_dialog = _extract_chat_dialog(flow.response.content, 4000)
    except Exception:
        resp_preview = ""
        resp_dialog = ""
    # 还原后的文本可能复述模型见到的凭据原文：落库前必须清洗。
    # 两步互补：形态正则（防用户自贴的凭据）+ 本会话原文精确串（防模型裸复述值本身）。
    resp_dialog = _redact_credentials(_redact_session_credentials(resp_dialog, s))
    resp_preview = _redact_credentials(_redact_session_credentials(resp_preview, s))
    # token 用量（尽力而为）：非流式顶层 usage；流式最后带 usage 的 chunk
    usage = {}
    try:
        if stream_usage:
            # 流式接管路径：usage 已在收流过程中逐块采集，不受文本留存上限影响
            usage = stream_usage
        elif streamed_text is not None:
            usage = _extract_usage(streamed_text)
        elif flow.response and flow.response.content:
            usage = _extract_usage(flow.response.content.decode("utf-8", errors="replace"))
    except Exception:
        usage = {}
    # RESTORE 明细：本会话脱敏过的占位符清单，标注每个是否真的被还原
    # （曾完全不带 items，前端详情弹窗永远显示「无敏感项明细」）
    items = []
    try:
        restored_tokens = s.get("restored_tokens") or set()
        for orig, tok in list(s.get("fwd", {}).items())[:30]:
            m = _PLACEHOLDER_PARTS_RX.match(tok)
            lbl = s.get("labels", {}).get(orig, "")
            is_cred = lbl in CREDENTIAL_LABELS
            item = {
                "tok": tok,
                "label": lbl,
                "hash": m.group(2) if m else "",
                "length": len(orig),
                "preview": _preview(orig, lbl),
                "restored": tok in restored_tokens,
            }
            # 凭据类不明文落库（与 MASK 口径一致），详情弹窗只显示打码预览
            if is_cred:
                item["cred"] = True
                item["digest"] = _cred_digest(orig)
            else:
                item["original"] = orig
            # 归因（roles）：复用会话里存的角色文本，前端据此展示真实命中位置
            try:
                role_texts = s.get("role_texts") or {}
                roles = _hit_roles_for(orig, role_texts)
                if roles:
                    item["roles"] = roles[:6]
            except Exception:
                pass
            items.append(item)
    except Exception:
        items = []
    # 上游 4xx + 请求带可疑 reasoning_effort：附加排查提示。透明代理不改请求
    # （下游配置问题由下游修），但事件里把原因说清楚，面板一眼可见。
    hint = ""
    try:
        hs = getattr(flow.response, "status_code", None)
        re_val = flow.metadata.get("shield_reasoning_effort")
        if hs is not None and hs >= 400 and re_val:
            hint = _reasoning_effort_hint(re_val)
    except Exception:
        pass
    _emit(
        "RESTORE",
        host=host,
        method=method,
        path=path,
        sid=sid,
        count=masked_count,
        restored=restored_count,
        restored_unique=restored_unique,
        unresolved=unresolved,
        # 靠宽松兜底（模型剥了花括号）修回来的个数。
        # 这个计数一直存在于会话里，但**从没被发进事件**——注释写着「计数进
        # RESTORE 事件，让用户看得见」，实际 _emit 参数里没有它，于是
        # 「靠兜底修回来的」这件事永远查不到。0.1.14 补上。
        degraded=degraded,
        success=bool(ok) and unresolved == 0,
        msg=hint,
        # status 兼容 SQLite 已有列/历史数据；restore_status 是前端统一读取的键
        # （曾只发 status，前端读 restore_status 全部不匹配，状态文案全是死代码）
        status=restore_status,
        restore_status=restore_status,
        items=items,
        scan_scope=s.get("scan_scope") or {},  # RESTORE 归因：复用 MASK 的扫描范围
        http_status=getattr(flow.response, "status_code", None),
        model=s.get("model") or "",
        upstream=s.get("upstream_name") or "",
        dialog=resp_dialog,
        # 用户消息（MASK 阶段存入会话）：回复日志弹窗同时展示用户发送的内容。
        # MASK 阶段已过形态清洗，这里再过一遍本会话原文精确串（纵深防御，代价一次替换）
        dialog_req=_redact_session_credentials(s.get("req_dialog") or "", s),
        resp_preview=resp_preview,
        usage=usage or None,
        stream_mode=s.get("stream_mode") or "non_stream",
        stream_actual=stream_actual,
        # 耗时（毫秒）：mask_ms=脱敏管线；upstream_ms=请求到响应总耗时
        # （首字节/整包完成）；first_byte_ms=流式首字节（整包=upstream_ms）
        # 用 perf_counter 基准（req_t0）算，μs 精度
        mask_ms=round(float(s.get("mask_ms") or 0), 1),
        upstream_ms=round((time.perf_counter() - float(s.get("req_t0") or time.perf_counter())) * 1000, 1),
        first_byte_ms=round(float(s.get("first_byte_ms") or 0), 1),
        **source,
    )


def _raw_stream_passthrough(data: bytes):
    """过滤关闭（FILTER_ENABLED=False）时的流式接管：chunk 原样透传。

    无会话可查、无占位符可还原（请求本来就没脱敏），接管只为把「整包缓冲」
    变成「逐块下发」，保住客户端的打字机效果（此前过滤关闭时 SSE 首字节
    延迟 = 整段生成时长，与脱敏路径/PT 兜底行为不一致，审计 P2）。
    末块 b"" 走 mitmproxy 的 ResponseEndOfMessage 分支（那里会过滤成 []）。
    """
    return data


def responseheaders(flow: http.HTTPFlow):
    """对 SSE 启用逐块还原转发；非 SSE 保持原有整包路径。

    mitmproxy 12 会在响应头阶段安装 stream 回调，随后按 bytes 块调用，
    消息结束时再传入 b""。_sse_stream_factory 在流末完成 RESTORE、审计、
    响应扫描和会话清理；关闭 stream_response 时自然回退到 response()。
    """
    if not STREAM_RESPONSE:
        return
    sid = flow.metadata.get("session_id")
    if not sid:
        # 过滤关闭的流量没有 session_id，但流式接管同样应该生效（纯透传）。
        # 前提是请求侧已声明 identity（见 request() 的 filter_off 分支），
        # 压缩响应在这里退回整包路径并留痕，与脱敏路径同款降级。
        if flow.metadata.get("shield_filter_off") and flow.response:
            headers0 = flow.response.headers
            ct0 = (headers0.get("content-type", "") or "").lower()
            framing0 = ("ndjson" if _is_ndjson_ct(ct0)
                        else ("sse" if "text/event-stream" in ct0 else None))
            if framing0:
                enc0 = (headers0.get("content-encoding", "") or "").lower().strip()
                if enc0 and enc0 != "identity":
                    _log(f"[stream] 过滤关闭但上游返回 content-encoding={enc0}，退回整包路径（失去流式）")
                    flow.metadata["shield_stream_degraded"] = enc0
                    return
                headers0.pop("content-length", None)
                flow.response.stream = _raw_stream_passthrough
        return
    if flow.metadata.get("shield_streamed") or not flow.response:
        return
    headers = flow.response.headers
    content_type = (headers.get("content-type", "") or "").lower()
    if _is_ndjson_ct(content_type):
        framing = "ndjson"
    elif "text/event-stream" in content_type:
        framing = "sse"
    else:
        return
    host = getattr(flow.request, "host", None) or flow.request.pretty_host
    path = flow.request.path
    emit_path = flow.metadata.get("shield_orig_path") or path
    method = getattr(flow.request, "method", "") or ""
    source = sessions.get(sid, {}).get("source", {})
    # 压缩体在 responseheaders 阶段仍是压缩字节，无法按事件解析；
    # 交回 response() 的整包路径，让 mitmproxy 先完成解压。
    content_encoding = (headers.get("content-encoding", "") or "").lower().strip()
    if content_encoding and content_encoding != "identity":
        # request() 已对流式请求声明 identity，走到这里说明上游无视了该头。
        # 静默退化会让「面板显示流式、客户端实际卡整段」无法归因，必须留痕。
        _log(f"[stream] {host} 返回 content-encoding={content_encoding}，退回整包路径（失去流式）")
        flow.metadata["shield_stream_degraded"] = content_encoding
        return
    if host in STREAM_EXCLUDE_HOSTS:
        return  # 用户显式排除的上游：保持整包路径
    _log(f"[LLM Shield] {framing.upper()} stream hook: {method} {host}{path.split('?')[0]} ct={content_type[:60]}")
    # 转换后长度不再等于上游 Content-Length；移除后由 mitmproxy 使用分块传输。
    headers.pop("content-length", None)
    flow.metadata["shield_streamed"] = True
    flow.response.stream = _sse_stream_factory(
        flow, sid, host, method, emit_path.split("?")[0], source, framing=framing
    )


def _handle_json(flow, sid):
    body = json.loads(flow.response.content)
    body = _restore_tree(body, sid)
    flow.response.content = json.dumps(body, ensure_ascii=False).encode("utf-8")


def _handle_sse(flow, sid):
    """整包 SSE 还原（流式接管失败时的回退路径，以及单测用）。"""
    raw = flow.response.content.decode("utf-8", errors="replace").replace("\r\n", "\n")
    blocks = raw.split("\n\n")
    out = [_restore_sse_event(b, sid) for b in blocks]
    body = "\n\n".join(out)
    tail = _flush_pending(sid)  # 流末仍有半截占位符：补一条事件，不能吞字
    if tail:
        body = body.rstrip("\n") + "\n\n" + tail
    flow.response.content = body.encode("utf-8")




def _read_settings():
    """从 config.json 解析设置，返回 dict 或 None（文件缺失/解析失败）。"""
    cfg_path = _DATA_ROOT / "config.json"
    if not cfg_path.exists():
        return None
    try:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception as e:
        _log(f"[LLM Shield] config parse failed: {e}")
        return None
    cw = {}
    disabled_labels = set()
    word_disabled = {}
    sens = cfg.get("sensitive")
    if isinstance(sens, dict):
        for label, words in sens.items():
            label = str(label or "").strip()
            if not label:
                continue
            # 兼容两种结构：
            # 1) {"地域": ["重庆", ...]}
            # 2) {"地域": {"enabled": false, "words": ["重庆"], "disabled_words": []}}
            if isinstance(words, dict):
                enabled = bool(words.get("enabled", True))
                if not enabled:
                    disabled_labels.add(label)
                word_list = words.get("words") or []
                dis_words = set()
                for w in words.get("disabled_words") or []:
                    w = str(w or "").strip()
                    if w:
                        dis_words.add(w)
                if dis_words:
                    word_disabled[label] = dis_words
            else:
                word_list = words or []
            for w in word_list:
                w = str(w or "").strip()
                if w:
                    cw[w] = label
    # 额外：sensitive_disabled 列表（仅组名）
    for lab in cfg.get("sensitive_disabled") or []:
        lab = str(lab or "").strip()
        if lab:
            disabled_labels.add(lab)
    # 顶层词级禁用 sensitive_word_disabled（panel.normalize_config 的标准结构：
    # {label: [word]}，UI「禁用词」写入这里；曾只解析 sensitive 内嵌 dict 的
    # disabled_words，顶层字段被忽略导致禁用词持续命中——SHIELD-WORD-DISABLE-001）
    raw_word_disabled = cfg.get("sensitive_word_disabled")
    if isinstance(raw_word_disabled, dict):
        for lab, ws in raw_word_disabled.items():
            lab = str(lab or "").strip()
            if not lab:
                continue
            wset = word_disabled.setdefault(lab, set())
            for w in ws or []:
                w = str(w or "").strip()
                if w:
                    wset.add(w)
    flat = cfg.get("custom_words")
    if isinstance(flat, dict):
        for w, l in flat.items():
            cw.setdefault(str(w), str(l))
    prefixes = []
    raw_sp = cfg.get("secret_prefixes")
    raw_sp = DEFAULT_SECRET_PREFIXES if raw_sp is None else raw_sp
    for p in raw_sp:
        p = str(p or "").strip()
        if p:
            prefixes.append(p)
    # 内置规则开关
    builtin = dict(DEFAULT_BUILTIN_RULES)
    raw_builtin = cfg.get("builtin_rules")
    if isinstance(raw_builtin, dict):
        for k, v in raw_builtin.items():
            k = str(k or "").strip().upper()
            if k in builtin:
                builtin[k] = bool(v)
    # 反向代理 upstream 路由表
    ups = []
    raw_ups = cfg.get("upstreams")
    if isinstance(raw_ups, list):
        seen_names = set()
        seen_base = set()
        seen_port = set()
        for u in raw_ups:
            if not isinstance(u, dict):
                continue
            name = str(u.get("name") or "").strip()
            base = str(u.get("base_path") or "").strip()
            target = str(u.get("target") or "").strip()
            if not name or not target:
                continue
            name_key = name.lower()
            if name_key in seen_names:
                continue
            seen_names.add(name_key)

            slug = re.sub(r"[^A-Za-z0-9_\-]", "", name).lower()[:40]
            if not base or not re.fullmatch(r"/[A-Za-z0-9_\-/]{1,60}", base):
                base = "/" + (slug or f"up_{len(ups) + 1}")
            if not base.startswith("/"):
                base = "/" + base
            candidate_base = base
            idx = 2
            while candidate_base in seen_base:
                candidate_base = f"{base}_{idx}"
                idx += 1
            base = candidate_base
            seen_base.add(base)

            port = int(u.get("port") or 0)
            if port == 0:
                port = 18701 + len(ups)
            if port < 1024 or port > 65535 or port in seen_port:
                port = 18701 + len(ups)
                while port in seen_port:
                    port += 1
            seen_port.add(port)

            paths = u.get("paths") or DEFAULT_PATHS
            if not isinstance(paths, list):
                paths = DEFAULT_PATHS

            extra_headers = {}
            raw_extra = u.get("extra_headers")
            if isinstance(raw_extra, dict):
                for k, v in raw_extra.items():
                    kk = str(k or "").strip()
                    if not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", kk):
                        continue
                    vv = str(v or "")
                    if len(vv) > 2048:
                        continue
                    extra_headers[kk] = vv

            ups.append({"name": name, "base_path": base, "port": port, "target": target,
                        "paths": list(paths), "use_proxy": bool(u.get("use_proxy")),
                        "extra_headers": extra_headers})
    if not ups:
        ups = list(DEFAULT_UPSTREAMS)
    # 出口代理：enabled 关闭时直接置 None，省得 request() 每次都判两个字段。
    # 地址非法同样返回 None（panel 侧 normalize_config 已给过 warning）。
    egress_cfg = cfg.get("egress_proxy")
    egress = None
    if isinstance(egress_cfg, dict) and egress_cfg.get("enabled"):
        egress = parse_egress_proxy(egress_cfg.get("url"))
    capture_mode = str(cfg.get("capture_mode") or "reverse").strip().lower()
    if capture_mode not in {"reverse", "explicit", "local"}:
        capture_mode = "reverse"
    # 2.0 审计配置
    audit_cfg = cfg.get("audit") or {}
    if not isinstance(audit_cfg, dict):
        audit_cfg = {}
    audit_signals_cfg = audit_cfg.get("signals") or {}
    if not isinstance(audit_signals_cfg, dict):
        audit_signals_cfg = {}
    return {
        "domains": cfg.get("target_domains") or DEFAULT_DOMAINS,
        "disabled": set(cfg.get("domains_disabled") or []),
        "paths": cfg.get("api_paths") or DEFAULT_PATHS,
        "words": cw,
        "sensitive_disabled": disabled_labels,
        "sensitive_word_disabled": word_disabled,
        "builtin_rules": builtin,
        "prefixes": prefixes,
        "ttl": int(cfg.get("session_ttl") or DEFAULT_TTL),
        "debug": bool(cfg.get("debug")),
        "diagnostic_unmatched": bool(cfg.get("diagnostic_unmatched")),
        "upstreams": ups,
        "egress_proxy": egress,
        "capture_mode": capture_mode,
        "filter_enabled": cfg.get("filter_enabled", True),
        "fail_closed": bool(cfg.get("fail_closed", True)),
        # 敏感词统计是否记录明文（默认开——打码 preview 排出来的榜没有信息量）
        "record_plaintext_words": bool(cfg.get("record_plaintext_words", True)),
        "response_scan": bool(cfg.get("response_scan", True)),
        "stream_response": bool(cfg.get("stream_response", True)),
        # 缺该键 = 老配置（该特性之前的版本）→ 上层回落默认黑名单；
        # 键存在但为空 = 用户在面板里显式清空 → 必须原样生效（返回空集，不是 None）。
        "stream_exclude_hosts": (
            {h.strip().lower() for h in (cfg.get("stream_exclude_hosts") or [])
             if isinstance(h, str) and h.strip()}
            if "stream_exclude_hosts" in cfg else None
        ),
        "audit_enabled": bool(audit_cfg.get("enabled", True)),
        "audit_passive": bool(audit_cfg.get("passive", True)),
        "audit_active_probes": bool(audit_cfg.get("active_probes", False)),
        "audit_severity_floor": str(audit_cfg.get("severity_floor") or "MEDIUM").upper(),
        "audit_fail_closed": bool(audit_cfg.get("fail_closed", False)),
        "audit_signals": {
            k: bool(audit_signals_cfg.get(k, dflt))
            for k, dflt in DEFAULT_AUDIT_SIGNALS.items()
        },
        "ner_enabled": bool(cfg.get("ner_enabled", False)),
        # 整词匹配词表：UI「整词匹配」开关写入 config.sensitive_word_whole。
        # 曾漏返回该键，_maybe_reload 读到 None 后回落空集，开关全程无效。
        "sensitive_word_whole": {
            str(w).strip() for w in (cfg.get("sensitive_word_whole") or []) if str(w).strip()
        },
    }


_cfg_mtime = [0.0]


def _maybe_reload(force=False):
    """热重载：config.json mtime 变了就刷新内存设置。每个请求调用，开销=一次 stat。"""
    global TARGET_DOMAINS, API_PATHS, CUSTOM_WORDS, SESSION_TTL, DEBUG, DIAGNOSTIC_UNMATCHED, DOMAINS_DISABLED, SECRET_PREFIXES, UPSTREAMS, CAPTURE_MODE, FILTER_ENABLED
    global AUDIT_ENABLED, AUDIT_PASSIVE, AUDIT_ACTIVE_PROBES, AUDIT_SEVERITY_FLOOR, AUDIT_SIGNALS
    global FAIL_CLOSED, RESPONSE_SCAN, STREAM_RESPONSE, STREAM_EXCLUDE_HOSTS
    global SENSITIVE_DISABLED, SENSITIVE_WORD_DISABLED, SENSITIVE_WORD_WHOLE, BUILTIN_RULES, EGRESS_PROXY
    try:
        mt = _DATA_ROOT.joinpath("config.json").stat().st_mtime
    except Exception:
        return
    if not force and mt == _cfg_mtime[0]:
        return
    _cfg_mtime[0] = mt
    s = _read_settings()
    if not s:
        return
    TARGET_DOMAINS = s["domains"]
    DOMAINS_DISABLED = s["disabled"]
    API_PATHS = s["paths"]
    SECRET_PREFIXES = s["prefixes"]
    SESSION_TTL = s["ttl"]
    DEBUG = s["debug"]
    DIAGNOSTIC_UNMATCHED = s["diagnostic_unmatched"]
    CUSTOM_WORDS.clear()
    CUSTOM_WORDS.update(s["words"])
    # 配置变更后允许对注入请求头的占位符/空值重新告警一次（用户改了配置就该重新提醒）
    _EXTRA_HEADER_SKIP_WARNED.clear()
    SENSITIVE_DISABLED = set(s.get("sensitive_disabled") or set())
    SENSITIVE_WORD_DISABLED = {
        k: set(v) for k, v in (s.get("sensitive_word_disabled") or {}).items()
    }
    SENSITIVE_WORD_WHOLE = set(s.get("sensitive_word_whole") or set())
    # 永久映射的重建必须排在禁用集赋值**之后**：_sync_custom_word_mappings 用
    # SENSITIVE_DISABLED / SENSITIVE_WORD_DISABLED 判断哪些词仍启用，放在前面会
    # 永远按上一代配置计算（禁用词要等第二次改配置才被清掉）。
    _refresh_custom_words_sorted()
    _CUSTOM_WORD_RX_CACHE.clear()  # 词表变更后清编译缓存
    BUILTIN_RULES = dict(DEFAULT_BUILTIN_RULES)
    raw_br = s.get("builtin_rules") or {}
    # 旧配置 IP 键迁移（与 panel.normalize_config 一致）：IP 拆 IP_PRIVATE/IP_INTERNAL
    if "IP" in raw_br and "IP_PRIVATE" not in raw_br:
        raw_br = dict(raw_br)
        raw_br["IP_PRIVATE"] = bool(raw_br.get("IP"))
        raw_br["IP_INTERNAL"] = False
    BUILTIN_RULES.update(raw_br)
    AUDIT_ENABLED = s["audit_enabled"]
    AUDIT_PASSIVE = s["audit_passive"]
    AUDIT_ACTIVE_PROBES = s["audit_active_probes"]
    AUDIT_SEVERITY_FLOOR = s["audit_severity_floor"]
    global AUDIT_FAIL_CLOSED
    AUDIT_FAIL_CLOSED = bool(s.get("audit_fail_closed", False))
    AUDIT_SIGNALS = s["audit_signals"]
    global NER_ENABLED
    NER_ENABLED = bool(s.get("ner_enabled", False))
    UPSTREAMS = s["upstreams"]
    EGRESS_PROXY = s.get("egress_proxy")
    CAPTURE_MODE = s["capture_mode"]
    FILTER_ENABLED = bool(s.get("filter_enabled", True))
    FAIL_CLOSED = bool(s.get("fail_closed", True))
    # 敏感词统计明文开关：事件由本进程 enqueue_event 写库，必须在这里同步
    try:
        import event_store as _es
        _es.set_record_plaintext_words(s.get("record_plaintext_words", True))
    except Exception:
        pass
    RESPONSE_SCAN = bool(s.get("response_scan", True))
    STREAM_RESPONSE = bool(s.get("stream_response", True))
    # 空集合是用户在面板里显式清空黑名单的意思，必须原样生效。
    # 曾写 `or {"opencode.ai"}`：空列表 falsy 直接回落默认黑名单，用户清空后
    # opencode.ai 仍被永久排除，实测 2798 次流式请求 100% 退化成整包路径。
    excl = s.get("stream_exclude_hosts")
    STREAM_EXCLUDE_HOSTS = set(excl) if excl is not None else set(_DEFAULT_STREAM_EXCLUDE_HOSTS)
    disabled_rules = [k for k, v in BUILTIN_RULES.items() if not v]
    _log(
        "[LLM Shield] config loaded: "
        f"mode={CAPTURE_MODE} upstreams={len(UPSTREAMS)} "
        f"egress={'%s://%s:%d' % (EGRESS_PROXY[0], EGRESS_PROXY[1][0], EGRESS_PROXY[1][1]) if EGRESS_PROXY else 'off'}"
        f"({sum(1 for u in UPSTREAMS if u.get('use_proxy'))} 个客户端走代理) "
        f"domains={len(TARGET_DOMAINS)} disabled={len(DOMAINS_DISABLED)} "
        f"paths={len(API_PATHS)} words={len(CUSTOM_WORDS)} "
        f"label_off={len(SENSITIVE_DISABLED)} rule_off={len(disabled_rules)} "
        f"prefixes={len(SECRET_PREFIXES)} debug={'on' if DEBUG else 'off'} diagnostic={'on' if DIAGNOSTIC_UNMATCHED else 'off'}"
    )


def _prune_debug_logs(max_days=7):
    """清理超过 max_days 天的 debug-YYYYMMDD.log。"""
    try:
        import glob
        cutoff = time.time() - max_days * 86400
        for f in glob.glob(str(_DATA_ROOT / "debug-*.log")):
            try:
                if os.path.getmtime(f) < cutoff:
                    os.remove(f)
            except Exception:
                pass
    except Exception:
        pass


def load(l):
    _maybe_reload(force=True)
    _warmup_recent_from_db()
    _prune_debug_logs()
    _log("=" * 50)
    _log("[LLM Shield] proxy started; config hot reload enabled")
    _log("=" * 50)


# 注意：预热**只在 mitmproxy 的 load() 钩子里做**，不在模块 import 期做。
# 0.1.12 曾在文件尾部无条件跑一次 _warmup_recent_from_db()，后果是任何
# import transparent 的进程都会去读事件库——包括 `python -m unittest discover`。
# 实测隔离数据目录下裸 import 就载入了生产库 420 条真实映射
# （EMAIL 99 / IP_PRIVATE 81 / PHONE 36 / CARD 13 / IDCARD 11）。
# 单测不该读生产数据（AGENTS 约束 23），import 也不该有 I/O 副作用。
