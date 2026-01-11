# src/apps/services/MalYaraScan.py
import os
import uuid
import hashlib
import shutil
from typing import Any, Dict, List

import yara  # pip install yara-python

from sqlalchemy import MetaData, Table, select
from src.extension import *

metadata = MetaData()


def get_yara_rule_table():
    return Table("yara_rule", metadata, autoload_with=db.engine)


# -----------------------
# 配置路径
# -----------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
RUNTIME_DIR = os.path.join(PROJECT_ROOT, "runtime", "yara_scan_py")

MAX_SAMPLE_BYTES = 50 * 1024 * 1024
SCAN_TIMEOUT_SECONDS = 10


def _ensure_dir(p: str):
    os.makedirs(p, exist_ok=True)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_filestorage_bytes(file_storage) -> bytes:
    data = file_storage.read()
    try:
        file_storage.stream.seek(0)
    except Exception:
        pass
    return data


def _safe_filename(name: str) -> str:
    name = (name or "").replace("\\", "/").split("/")[-1]
    return name.replace("..", "_")


def _to_matches_from_yara(matches: List[yara.Match]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for m in matches:
        out.append({
            "rule": m.rule,
            "namespace": getattr(m, "namespace", None),
            "tags": [],
            "meta": {},
            "strings": []
        })
    return out


class MalYaraScan:

    @staticmethod
    def scan_sample_with_yara(file_storage,
                              label: str = "",
                              rule_set: str = "enabled") -> Dict[str, Any]:

        if file_storage is None:
            raise ValueError("缺少上传文件：file")

        filename = _safe_filename(file_storage.filename or "")
        if not filename:
            filename = "sample.bin"

        raw = _read_filestorage_bytes(file_storage)
        if len(raw) > MAX_SAMPLE_BYTES:
            raise ValueError("FILE_TOO_LARGE")

        sample_sha256 = _sha256_hex(raw)

        # --------- 任务目录 ----------
        job_id = uuid.uuid4().hex
        job_dir = os.path.join(RUNTIME_DIR, job_id)
        _ensure_dir(job_dir)

        try:
            # 只从 yara_rule（编译表）取启用规则
            yara_rule_table = get_yara_rule_table()

            stmt = select(
                yara_rule_table.c.compiled_sha256,
                yara_rule_table.c.compiled_rule
            )

            if rule_set == "enabled":
                stmt = stmt.where(yara_rule_table.c.enabled == 1)
            elif rule_set == "all":
                pass
            else:
                raise ValueError("rule_set 参数非法：仅允许 enabled|all")

            with db.engine.connect() as conn:
                rows = conn.execute(stmt).mappings().all()

            if not rows:
                raise ValueError("规则集为空：数据库里没有可用 YARA 规则（请先上传规则或启用规则）")

            # compiled_sha256 去重加载
            unique: Dict[str, bytes] = {}
            for r in rows:
                csha = (r.get("compiled_sha256") or "").strip()
                blob = r.get("compiled_rule")
                if not csha or not blob:
                    continue
                if csha not in unique:
                    unique[csha] = blob

            if not unique:
                raise ValueError("规则集为空：没有可用的预编译规则（compiled_rule 为空）")

            all_matches: List[yara.Match] = []

            for csha, blob in unique.items():
                compiled_path = os.path.join(job_dir, f"{csha}.yarc")
                with open(compiled_path, "wb") as f:
                    f.write(blob)

                rules = yara.load(filepath=compiled_path)

                ms = rules.match(data=raw, timeout=SCAN_TIMEOUT_SECONDS)
                if ms:
                    all_matches.extend(ms)

            matches = _to_matches_from_yara(all_matches)

            return {
                "ok": True,
                "sample_id": job_id,
                "label": label or "",
                "sample_filename": filename,
                "sample_sha256": sample_sha256,
                "rule_set": rule_set,
                "matches": matches,
                "engine_stdout": "",
                "engine_stderr": "",
            }

        except yara.TimeoutError:
            raise ValueError("SCAN_TIMEOUT")
        finally:
            shutil.rmtree(job_dir, ignore_errors=True)
