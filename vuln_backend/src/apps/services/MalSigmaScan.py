# src/apps/services/MalSigmaScan.py
import os
import io
import json
import uuid
import shutil
import hashlib
import zipfile
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional
import sys

import yaml
from sqlalchemy import MetaData, Table, select

from src.extension import *


metadata = MetaData()

def get_sigma_rule_table():
    return Table("sigma_rule", metadata, autoload_with=db.engine)


# -----------------------
# 配置：按你的项目实际路径改这里
# -----------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
ZIRCOLITE_DIR = os.path.join(PROJECT_ROOT, "third_party", "Zircolite")  # 推荐目录
ZIRCOLITE_PY  = os.path.join(ZIRCOLITE_DIR, "zircolite.py")
ZIRCOLITE_PYTHON = os.path.join(
    ZIRCOLITE_DIR,
    ".venv",
    "Scripts",
    "python.exe"
)

RUNTIME_DIR = os.path.join(PROJECT_ROOT, "runtime", "sigma_scan")  # 运行时目录（自动创建）
MAX_EVTX_BYTES = 80 * 1024 * 1024  # 80MB
SCAN_TIMEOUT_SECONDS = 180  # 超时保护（按你机器性能调整）


def _sha256_hex(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _read_filestorage_bytes(file_storage) -> bytes:
    data = file_storage.read()
    try:
        file_storage.stream.seek(0)
    except Exception:
        pass
    return data


def _ensure_dir(p: str):
    os.makedirs(p, exist_ok=True)


def _safe_filename(name: str) -> str:
    # 简单去危险字符（避免路径穿越）
    name = (name or "").replace("\\", "/").split("/")[-1]
    return name.replace("..", "_")


def _dump_rule_to_yaml(rule_obj: Dict[str, Any]) -> str:
    # Sigma 原生 YAML：保持 key 顺序更友好
    return yaml.safe_dump(rule_obj, sort_keys=False, allow_unicode=True)


def _extract_alerts_from_zircolite(raw_results: List[Dict[str, Any]], return_level: str) -> Dict[str, Any]:
    """
    Zircolite 输出是 JSON 数组，每个元素大概长这样：
      {
        "title": "...",
        "description": "...",
        "rule_level": "...",
        "count": 7,
        "matches": [ { ...event fields... }, ... ]
      }
    我们转成前端需要的 alerts。
    """
    alerts = []
    hit_events = []  # 只有 return_level=with_events 才填

    for item in raw_results:
        title = item.get("title")
        desc = item.get("description")
        level = item.get("rule_level") or item.get("level")
        count = item.get("count") or 0
        matches = item.get("matches") or []

        # evidence：从 matches 的第一条里挑几个字段（你也可以扩展）
        evidence = []
        if matches:
            sample = matches[0]
            # 尽量挑常见字段；如果不存在就跳过
            for k in ["EventID", "Channel", "Computer", "Image", "CommandLine", "ParentImage", "User", "ProcessId"]:
                if k in sample and sample[k] not in (None, ""):
                    evidence.append({"field": k, "value": str(sample[k])})

        alert = {
            "rule_id": item.get("id") or item.get("rule_id") or "-",   # Zircolite 有时不直接给 id
            "title": title or "-",
            "level": level or "-",
            "tags": item.get("tags") or [],  # 可能没有
            "hit_count": count,
            "evidence": evidence,
            "hit_event_ids": [],  # 可选：你若想返回索引，可自己生成
        }
        alerts.append(alert)

        if return_level == "with_events":
            # 注意：可能很大
            for idx, ev in enumerate(matches[:2000]):  # 给个上限保护（你可调）
                hit_events.append({
                    "event_id": idx,
                    "data": ev
                })

    return {"alerts": alerts, "hit_events": hit_events}


class MalSigmaScan:
    """
    对接前端：POST /detectEvtxWithSigma
    """

    @staticmethod
    def detect_evtx_with_sigma(file_storage,
                              label: str = "",
                              rule_set: str = "enabled",
                              return_level: str = "summary") -> Dict[str, Any]:

        # --------- 基础校验 ----------
        if file_storage is None:
            raise ValueError("缺少上传文件：file")

        filename = _safe_filename(file_storage.filename or "")
        if not filename.lower().endswith(".evtx"):
            raise ValueError("文件类型不正确：仅支持 .evtx")

        raw_evtx = _read_filestorage_bytes(file_storage)
        if len(raw_evtx) > MAX_EVTX_BYTES:
            raise ValueError("文件过大：超过后端限制")

        if not os.path.exists(ZIRCOLITE_PY):
            raise ValueError(f"未找到 Zircolite：{ZIRCOLITE_PY}（请把 Zircolite 解压到 third_party/zircolite）")

        # --------- 创建本次任务目录 ----------
        job_id = uuid.uuid4().hex
        job_dir = os.path.join(RUNTIME_DIR, job_id)
        rules_dir = os.path.join(job_dir, "rules")
        logs_dir = os.path.join(job_dir, "logs")
        out_dir = os.path.join(job_dir, "out")

        _ensure_dir(rules_dir)
        _ensure_dir(logs_dir)
        _ensure_dir(out_dir)

        evtx_path = os.path.join(logs_dir, filename)
        out_json = os.path.join(out_dir, "zircolite_results.json")

        with open(evtx_path, "wb") as f:
            f.write(raw_evtx)

        evtx_sha256 = _sha256_hex(raw_evtx)

        # --------- 从 DB 导出规则到 rules_dir ----------
        sigma_table = get_sigma_rule_table()
        stmt = select(sigma_table)
        if rule_set == "enabled":
            stmt = stmt.where(sigma_table.c.enabled == 1)
        elif rule_set == "all":
            pass
        else:
            raise ValueError("rule_set 参数非法：仅允许 enabled|all")

        # 取出规则
        with db.engine.connect() as conn:
            rows = conn.execute(stmt).mappings().all()

        if not rows:
            raise ValueError("规则集为空：数据库里没有可用 Sigma 规则（请先上传规则或启用规则）")

        # 写入 YAML 文件
        written = 0
        for r in rows:
            rule_obj = r["rule_json"]  # MySQL JSON -> dict
            sha = r["sha256"]
            # 文件名：sha256.yml（稳定且唯一）
            yml_path = os.path.join(rules_dir, f"{sha}.yml")
            try:
                yml_text = _dump_rule_to_yaml(rule_obj)
                with open(yml_path, "w", encoding="utf-8") as f:
                    f.write(yml_text)
                written += 1
            except Exception as e:
                # 单条规则坏了不应拖垮全局，你也可以改成 raise
                continue

        if written == 0:
            raise ValueError("规则导出失败：未能写入任何 YAML 规则文件")

        # --------- 调用 Zircolite ----------
        # 关键：ruleset 直接给目录
        # cmd = [
        #     sys.executable,               # 用当前 Python 解释器
        #     ZIRCOLITE_PY,
        #     "-r", rules_dir,
        #     "-e", evtx_path,
        #     "-o", out_json
        # ]
        cmd = [
            ZIRCOLITE_PYTHON,
            ZIRCOLITE_PY,
            "-r", rules_dir,
            "-e", evtx_path,
            "-o", out_json
        ]

        try:
            # cwd 指向 Zircolite 目录，避免相对路径/依赖问题
            proc = subprocess.run(
                cmd,
                cwd=ZIRCOLITE_DIR,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                text=True,
                timeout=SCAN_TIMEOUT_SECONDS
            )
        except subprocess.TimeoutExpired:
            raise ValueError("检测超时：DETECT_TIMEOUT")
        except Exception as e:
            raise ValueError(f"调用 Zircolite 失败：{str(e)}")

        if proc.returncode != 0:
            # 把 stderr 打回去方便你调试
            raise ValueError(f"Zircolite 执行失败：{proc.stderr[:2000]}")

        if not os.path.exists(out_json):
            raise ValueError("Zircolite 未生成输出文件")

        # --------- 读取 & 组装返回 ----------
        with open(out_json, "r", encoding="utf-8") as f:
            raw_results = json.load(f)  # JSON 数组

        # Zircolite 输出里有匹配事件，不等于“总事件数”，这里先给 -1 占位
        # 如果你想要 event_count，需要走 EVTX 解析库统计
        event_count = None

        pack = _extract_alerts_from_zircolite(raw_results, return_level)

        resp = {
            "ok": True,
            "log_id": job_id,           # 你也可以换成数据库自增任务ID
            "label": label or "",
            "filename": filename,
            "sha256": evtx_sha256,
            "rule_set": rule_set,
            "event_count": event_count,
            "alerts": pack["alerts"],
        }

        if return_level == "with_events":
            resp["hit_events"] = pack["hit_events"]

        # 可选：把 Zircolite stdout/stderr 也带回去，调试时很有用
        resp["engine_stdout"] = proc.stdout[-2000:]
        resp["engine_stderr"] = proc.stderr[-2000:]

        return resp
