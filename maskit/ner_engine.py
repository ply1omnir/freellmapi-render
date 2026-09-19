"""
Data Maskit - 本地高精度 ONNX 实体识别（NER）引擎
基于经典中文 BERT-Base 量化模型（~98MB，基于 OntoNotes 5.0 中研院权威预训练模型），本地 CPU 毫秒级推理。
负责从非结构化中文文本中高召回率提取人名 (NAME)、企事业单位/机构/医院 (ORG)、详细地址与建筑 (ADDR)。

成本模型（实测，2026-09-19）：耗时随字数近似线性，约 0.25ms/字
（30 字 8ms / 120 字 19ms / 500 字 81ms / 2000 字 500ms）。
本模块跑在脱敏主链路上、且 mask() 会对请求体每个字符串叶子各调一次，
所以这里必须自己带硬边界（长度上限 + 时间预算 + 结果缓存），
且**任何失败都必须可见**——静默降级等于「用户以为开了、实际没脱」。
"""

from __future__ import annotations
import json
import logging
import re
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# 日志名与引擎其余部分一致（transparent 的 _log 用 llm_shield）。曾写成 "maskit"，
# 而全仓没有任何 basicConfig，那条唯一的初始化失败告警实际上无处可见。
_logger = logging.getLogger("llm_shield")

_MODEL_DIR = Path(__file__).parent / "models" / "ner_mini_zh"
_SESSION = None
_TOKENIZER = None
_ID2LABEL = {}
_INITIALIZED = False
_INIT_FAILED = False
_LAST_ERROR = ""

# ── 成本护栏 ──────────────────────────────────────────────────────────────────
# 单条文本长度上限：超过即跳过语义识别并留一次日志。宁可这一条不做识别，
# 也不能让一条超长文本把整个代理冻住（单线程事件循环被占满 = 打字机卡死 +
# 其他客户端超时）。实测 10 万字符单次调用要 69 秒。
MAX_TEXT_CHARS = 2000
# 单次调用时间预算（秒）：长度在上限内但推理异常变慢时按时收手，只返回已收集实体。
CALL_BUDGET_S = 2.0
# 结果缓存：同一条文本在长会话里反复出现（系统提示词、重复的历史消息），
# 不缓存就是每次重新推理。键是文本本身，容量固定（OrderedDict LRU），命中即零成本。
_CACHE_MAX = 256
_CACHE = OrderedDict()


def _cache_put(key, entities):
    """写入结果缓存（含负缓存：`entities` 为空表示「这段确实没有实体」）。

    只接受**完整**跑完的结果 —— 预算超时/推理异常返回的残缺列表不进缓存，
    否则该文本此后命中缓存就一直欠脱敏（审计 M6）。
    负缓存解决的是同源问题：无实体的长文本此前每次请求都重跑推理
    （≤2000 字约 500ms/次）。它与「没跑完」必须区分开，所以调用方只在
    `_decode_chunks` 报 complete 时才调这里。
    """
    _CACHE[key] = [dict(e) for e in entities]
    _CACHE.move_to_end(key)
    while len(_CACHE) > _CACHE_MAX:
        _CACHE.popitem(last=False)
# 预算窗口的宽限（秒）：调用方漏调 end_budget（异常路径）时超过它就自愈，
# 免得某个线程被永久停掉语义识别——Flask 会复用线程，永久停用等于静默降级。
_BUDGET_LEAK_GRACE_S = 60.0
# 调用方给「一串调用」设的总预算（threading.local：只对本线程生效）。
_local = threading.local()
# 跳过原因计数 + 「只记一次」集合：失败必须可见，但每个请求都刷日志同样不可接受。
_SKIP_STATS = {}
_SKIP_LOGGED = set()


def _warn_once(key, msg):
    """记录一次可诊断的跳过原因（同类只写一条日志）。"""
    _SKIP_STATS[key] = _SKIP_STATS.get(key, 0) + 1
    if key not in _SKIP_LOGGED:
        _SKIP_LOGGED.add(key)
        try:
            _logger.warning("[ner_engine] %s（同类问题后续不再重复记录）", msg)
        except Exception:
            pass


def record_skip(key: str, msg: str = "") -> None:
    """记录一次跳过原因并纳入 status().skips 统计（供外部如 transparent 的坐标降级调用）。"""
    _warn_once(key, msg or f"NER 跳过: {key}")


def begin_budget(seconds):
    """开启一段有总预算的调用序列（如整份 Office 文档逐 run 脱敏）。

    期间「截止时间已过」等同于「预算耗尽」，extract_entities 直接跳过推理；
    必须由调用方配对调用 end_budget（transparent._ner_doc_budget 已封装）。
    """
    _local.doc_active = True
    # 不钳到 >=0：负值/0 用来表达「预算窗口已经过去」，便于测试与自愈判定
    _local.deadline = time.monotonic() + float(seconds)


def end_budget():
    _local.doc_active = False
    _local.deadline = None


def _current_deadline():
    """返回本次调用实际可用的绝对截止时间；None 表示预算已耗尽、应跳过本次推理。

    没有显式预算时按单次上限兜底。deadline 过期且**不在**显式预算序列里时按
    「未设置」处理：调用方漏调 end_budget 也只会退回默认上限，绝不永久停掉识别。
    """
    now = time.monotonic()
    dl = getattr(_local, "deadline", None)
    if dl is None:
        return now + CALL_BUDGET_S
    if dl <= now:
        # 显式预算窗口内「过期」= 预算耗尽，跳过本次推理；窗口本身会自愈：
        # 漏调 end_budget 最多影响 _BUDGET_LEAK_GRACE_S，绝不永久停掉识别。
        if getattr(_local, "doc_active", False) and (now - dl) < _BUDGET_LEAK_GRACE_S:
            return None
        _local.doc_active = False
        _local.deadline = None
        return now + CALL_BUDGET_S
    return min(dl, now + CALL_BUDGET_S)


ADDR_TAGS = frozenset({"GPE", "LOC", "FAC"})
# 行政区后缀：整段以此结尾且无门牌细节 → 只是「地名」不是「地址」（审计 L3）。
_ADMIN_SUFFIXES = (
    "自治区", "特别行政区", "自治州", "自治县", "地区", "省", "市", "县", "区", "国",
)
# 门牌/街道/楼栋细节后缀：出现任一即认为这是**具体地址**，必须打码。
_ADDR_DETAIL_CHARS = (
    "路", "街", "道", "巷", "弄", "号", "楼", "室", "栋", "幢", "座", "单元",
    "院", "园", "村", "镇", "乡", "大厦", "广场", "小区", "花园", "公馆", "层", "段",
)


def _is_bare_region(s: str) -> bool:
    """整段只是一个行政区名（无门牌/街道细节）→ 不当地址处理。

    GPE 会把「北京」「中国」「广东省」这类高熵为零的地名标出来。脱敏它们
    保护不了任何东西（几千万人共用一个地名），却会把词榜灌满噪声 ——
    审计 L3 实测的过度脱敏。判据刻意收得很紧：含数字、含街道/楼栋细节、
    或长度超过 10 字，一律不算「裸地名」，照常当地址打码。
    """
    if not s or len(s) > 10:
        return False
    if any(ch.isdigit() for ch in s):
        return False
    if any(c in s for c in _ADDR_DETAIL_CHARS):
        return False
    if s.endswith(_ADMIN_SUFFIXES):
        return True
    # 「北京」「上海」这类不带后缀的裸城市名：只有足够短才算地名，
    # 再长就可能是「海淀中关村」这种需要打码的具体片区。
    return len(s) <= 4
ORG_SUFFIXES = (
    "医院", "诊所", "卫生院", "妇幼保健院", "中医院", "大学", "学院", "学校",
    "分公司", "支行", "分行", "有限责任公司", "有限公司", "公司", "集团",
    "委员会", "事务所", "局", "厅", "处", "部", "院", "所", "中心", "实验室"
)
ADDR_SUFFIXES = (
    "路", "街", "大道", "巷", "弄", "里", "胡同", "桥", "段", "村", "镇", "乡",
    "区", "县", "市", "省", "大厦", "广场", "大楼", "中心", "园区",
    "花园", "小区", "城", "苑", "府", "公馆", "号", "栋", "幢", "层", "楼", "室", "单元", "座"
)


def is_ner_available() -> bool:
    """检查 NER 模型文件是否就绪（只看文件；依赖是否可导入由 status() 反映）。"""
    return (
        (_MODEL_DIR / "model_quantized.onnx").exists()
        and (_MODEL_DIR / "tokenizer.json").exists()
        and (_MODEL_DIR / "config.json").exists()
    )


def status() -> Dict:
    """运行状态（面板/健康检查用）。

    available 只代表模型文件齐备；真正能否推理要看 initialized。
    这两者都不成立时必须让用户看得见，否则「开了 NER 却没打码」无从归因。
    """
    return {
        "available": is_ner_available(),
        "initialized": bool(_INITIALIZED),
        "failed": bool(_INIT_FAILED),
        "last_error": _LAST_ERROR,
        "model_dir": str(_MODEL_DIR),
        "max_text_chars": MAX_TEXT_CHARS,
        "call_budget_s": CALL_BUDGET_S,
        "cache_size": len(_CACHE),
        "skips": dict(_SKIP_STATS),
    }


def _init_ner():
    global _SESSION, _TOKENIZER, _ID2LABEL, _INITIALIZED, _INIT_FAILED, _LAST_ERROR
    if _INITIALIZED:
        return True
    if _INIT_FAILED:
        return False

    if not is_ner_available():
        _INIT_FAILED = True
        _LAST_ERROR = f"模型文件缺失（应为 {_MODEL_DIR} 下的 model_quantized.onnx / tokenizer.json / config.json）"
        _warn_once("model_missing", _LAST_ERROR + "，语义实体识别未启用")
        return False

    try:
        import onnxruntime as ort
        from tokenizers import Tokenizer

        tok_path = _MODEL_DIR / "tokenizer.json"
        cfg_path = _MODEL_DIR / "config.json"
        model_path = _MODEL_DIR / "model_quantized.onnx"

        _TOKENIZER = Tokenizer.from_file(str(tok_path))
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        _ID2LABEL = cfg.get("id2label", {})

        # 4 线程 CPU 推理。实测约 0.25ms/字（含分块与后处理），见模块头部成本模型。
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 4
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

        _SESSION = ort.InferenceSession(str(model_path), sess_options=opts, providers=["CPUExecutionProvider"])
        _INITIALIZED = True
        return True
    except Exception as e:
        _INIT_FAILED = True
        _LAST_ERROR = f"{type(e).__name__}: {e}"
        # 依赖缺失（onnxruntime/tokenizers 未安装）会走到这里，必须给出可执行的提示：
        # 正式包缺少依赖时只会打到这里，否则用户只看到「开了没效果」。
        _warn_once("init_failed",
                   f"初始化失败，语义实体识别不可用：{_LAST_ERROR}"
                   f"（缺少 onnxruntime/tokenizers 依赖或模型文件损坏；依赖见 requirements-dev.txt）")
        return False


def _map_category(tag: str) -> Optional[str]:
    """将 OntoNotes 细粒度标签映射到统一的标准脱敏标签。"""
    if tag == "PERSON":
        return "NAME"
    if tag == "ORG":
        return "ORG"
    if tag in ADDR_TAGS:
        return "ADDR"
    return None


def _decode_chunks(text: str, deadline: float) -> Tuple[List[Dict], bool]:
    """分块滑窗推理，返回 (原始实体片段, 是否完整跑完)。

    `complete` 必须如实回报：预算超时或单块推理异常都会 `break` 并带着**残缺**的
    实体列表返回，调用方据此决定要不要写缓存（审计 M6）。
    """
    import numpy as np

    CHUNK_SIZE = 400
    STRIDE = 350
    text_len = len(text)
    raw_entities = []
    complete = True

    pos = 0
    while pos < text_len:
        chunk = text[pos:pos + CHUNK_SIZE]
        if not chunk:
            break

        encoded = _TOKENIZER.encode(chunk)
        input_ids = np.array([encoded.ids], dtype=np.int64)
        attention_mask = np.array([encoded.attention_mask], dtype=np.int64)
        token_type_ids = np.zeros_like(input_ids, dtype=np.int64)

        inputs = {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
            "token_type_ids": token_type_ids,
        }

        try:
            outputs = _SESSION.run(None, inputs)
            logits = outputs[0][0]
            preds = np.argmax(logits, axis=-1)
        except Exception as e:
            # 单块推理失败：记一次日志后收手，返回已收集的部分实体。
            # 曾完全静默 break，用户侧只表现为「部分文本没打码」。
            _warn_once("infer_failed", f"推理异常，本段仅返回已识别结果：{type(e).__name__}: {e}")
            complete = False
            break

        offsets = encoded.offsets
        curr = None

        for pred, (s, e) in zip(preds, offsets):
            lbl = _ID2LABEL.get(str(pred), "O")
            if s == e:
                continue
            abs_s = pos + s
            abs_e = pos + e

            if lbl == "O":
                if curr:
                    raw_entities.append(curr)
                    curr = None
                continue

            # 标签形态守卫（审计 L4）：下面按 `lbl[0]` 取 BIO 前缀、`lbl[2:]` 取类别，
            # 隐含要求 "B-NAME" 这种长度 ≥3 且第 2 位是 '-' 的形态。
            # `config.json` 被换成含空标签的模型时 `lbl[0]` 直接 IndexError；
            # "B" 这类短标签则会让 tag 变成 ""，_map_category 返回 None 后
            # 同样把 curr 冲掉。两种都按「无法识别的标签」收尾并跳过 ——
            # 宁可漏一个实体，也不能让整条 NER 抛异常。
            if len(lbl) < 3 or lbl[1] != "-":
                if curr:
                    raw_entities.append(curr)
                    curr = None
                continue

            prefix = lbl[0]  # B, I, E, S
            tag = lbl[2:]
            cat = _map_category(tag)

            if not cat:
                if curr:
                    raw_entities.append(curr)
                    curr = None
                continue

            if prefix in ("B", "S"):
                if curr:
                    raw_entities.append(curr)
                curr = {"type": cat, "start": abs_s, "end": abs_e, "text": text[abs_s:abs_e]}
                if prefix == "S":
                    raw_entities.append(curr)
                    curr = None
            elif prefix in ("I", "E"):
                if curr and curr["type"] == cat:
                    curr["end"] = abs_e
                    curr["text"] = text[curr["start"]:abs_e]
                    if prefix == "E":
                        raw_entities.append(curr)
                        curr = None
                else:
                    if curr:
                        raw_entities.append(curr)
                    curr = {"type": cat, "start": abs_s, "end": abs_e, "text": text[abs_s:abs_e]}
                    if prefix == "E":
                        raw_entities.append(curr)
                        curr = None

        if curr:
            raw_entities.append(curr)

        if pos + CHUNK_SIZE >= text_len:
            break
        # 时间预算：超时就收手。必须是**块间**检查——单块推理无法中断，
        # 但只要不再开新块，耗时就不会继续线性膨胀。
        if time.monotonic() > deadline:
            _warn_once("deadline", "达到单次推理时间预算，本次仅返回已识别结果")
            complete = False
            break
        pos += STRIDE

    return raw_entities, complete


def extract_entities(text: str) -> List[Dict]:
    """提取文本中的命名实体（人名、机构名、地址）。

    返回: [{"type": "NAME"|"ORG"|"ADDR", "start": int, "end": int, "text": str}]
    返回的 dict 允许调用方读取，改动不会污染缓存（每次返回独立副本）。
    """
    if not text or not isinstance(text, str) or len(text.strip()) < 2:
        return []

    # 纯英文/代码/无汉字文本直接跳过：本引擎基于中文 BERT（OntoNotes 5.0），
    # 仅负责人名 (NAME)、机构 (ORG)、详细地址 (ADDR) 三类中文实体。
    # 纯英文或代码中无中文实体，反而会被 BERT subword 切碎产生误报（如将英文参数误报为人名）。
    if not any("\u4e00" <= ch <= "\u9fff" for ch in text):
        return []

    if len(text) > MAX_TEXT_CHARS:
        _warn_once("too_long",
                   f"文本 {len(text)} 字超过 {MAX_TEXT_CHARS} 字上限，该条未做语义实体识别")
        return []

    cached = _CACHE.get(text)
    if cached is not None:
        _CACHE.move_to_end(text)
        return [dict(e) for e in cached]

    if not _init_ner():
        return []

    deadline = _current_deadline()
    if deadline is None:
        _warn_once("budget_exhausted", "本次脱敏的语义识别总预算已耗尽，剩余文本未做实体识别")
        return []

    raw_entities, complete = _decode_chunks(text, deadline)
    if not raw_entities:
        # 负缓存（审计 M6 同源问题）：无实体的长文本此前**每次请求都重跑推理**
        # （≤2000 字约 500ms/次，实测成本模型 0.25ms/字）。
        # ⚠️ 只在 `complete` 时才写：预算超时 / 推理异常返回的空结果是「没跑完」，
        # 缓存下来会让这段文本在此后永久不再被识别（该打码的不打）。
        if complete:
            _cache_put(text, [])
        return []

    # 去重与区间排序。重叠时**裁剪**而不是整条丢弃（审计 L2）：
    # 旧写法 `if ent["start"] < last_end: continue` 会把「起点落在前一个实体内、
    # 但终点更远」的那条整个丢掉，于是 [last_end, ent_end) 这段既不属于任何实体、
    # 也不被打码 —— 注释里「不会漏明文」的断言并不严格成立。
    raw_entities.sort(key=lambda x: (x["start"], -x["end"]))
    deduped = []
    last_end = -1
    for ent in raw_entities:
        if ent["start"] < last_end:
            if ent["end"] <= last_end:
                continue                      # 完全被前一个覆盖：真丢
            ent = dict(ent, start=last_end, text=text[last_end:ent["end"]])
        deduped.append(ent)
        last_end = ent["end"]

    # 实体精炼与边界平滑
    refined = []
    for ent in deduped:
        etype = ent["type"]
        start, end = ent["start"], ent["end"]

        # 后缀贪婪扩充
        if etype == "ORG":
            tail = text[end:end + 12]
            for sfx in ORG_SUFFIXES:
                if tail.startswith(sfx):
                    end += len(sfx)
                    break
        elif etype == "ADDR":
            tail = text[end:end + 20]
            # 门牌与楼栋吸附。注意：字符类里的连续数字串靠「结构化规则先跑」才安全
            # （卡号那时已变成 {{...}}，`{` 不在字符类里），改执行顺序要重新评估。
            m = re.match(r"^([0-9A-Za-z一二三四五六七八九十\-号栋幢层楼室单元座段]+)", tail)
            if m:
                end += len(m.group(1))

        ent_text = text[start:end]
        # 过滤极短或无意义实体（人名需至少 2 字；机构和地址需至少 2 字）
        if len(ent_text) <= 1:
            continue
        if any(c in ent_text for c in ("\n", "\r", "\t")):
            continue
        # 纯行政区名不当地址（审计 L3）：GPE 会把「北京」「中国」这类高熵为零的
        # 地名标出来，脱敏它们只是把高频词换成占位符、把词榜灌满噪声，保护不了
        # 任何东西。判据要求**整段**都是行政区名（无门牌/街道/楼栋细节）——
        # 「北京市朝阳区建国路88号」有数字和街道后缀，照常打码。
        if etype == "ADDR" and _is_bare_region(ent_text):
            continue

        refined.append({
            "type": etype,
            "start": start,
            "end": end,
            "text": ent_text,
        })

    # 后缀扩充发生在去重**之后**，可能越过下一个实体的起点（前一个把后一个吞掉）。
    # 这里按起点重排并裁剪与前一个已接受实体重叠的项（审计 L2）：
    # 旧写法整条 `continue`，注释断言「被吞掉的文本仍在前一个实体区间内」——
    # 这只在被吞的那条**完全落在**前一个区间内时成立。若它的终点更远
    # （前一个 end 被后缀扩充推过了它的 start），[前一个 end, 它的 end) 这段
    # 就既不属于任何实体、也不被打码，是实打实的漏明文。改成保留尾部区间。
    refined.sort(key=lambda x: (x["start"], -x["end"]))
    trimmed = []
    for ent in refined:
        if trimmed and ent["start"] < trimmed[-1]["end"]:
            if ent["end"] <= trimmed[-1]["end"]:
                continue                      # 完全被覆盖：丢弃
            ent = dict(ent, start=trimmed[-1]["end"],
                       text=text[trimmed[-1]["end"]:ent["end"]])
        trimmed.append(ent)

    # 相邻同类型实体合并（特别是相邻切碎的地址块）
    final_merged = []
    for ent in trimmed:
        if not final_merged:
            final_merged.append(ent)
            continue
        prev = final_merged[-1]
        if prev["type"] == ent["type"] and ent["type"] == "ADDR":
            gap = text[prev["end"]:ent["start"]]
            # 如果两个地址块相距不足 6 字符且没有标点中断，直接缝合
            if len(gap) <= 6 and not any(p in gap for p in ("，", "。", "！", "？", ";", ",")):
                prev["end"] = ent["end"]
                prev["text"] = text[prev["start"]:ent["end"]]
                continue
        final_merged.append(ent)

    # 只有**完整**跑完的结果才入缓存（审计 M6）：预算超时（`deadline` 分支）与
    # 单块推理异常都会带着残缺实体列表走到这里，缓存下来等于让该文本此后每次
    # 命中缓存都返回同一份残缺结果——即使系统空闲也不再补全，持续欠脱敏。
    if complete:
        _cache_put(text, final_merged)
    return [dict(e) for e in final_merged]
