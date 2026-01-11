# src/apps/services/MalSigmaUpload.py
import io
import zipfile
import hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import yaml
from sqlalchemy import MetaData, Table
from sqlalchemy.dialects.mysql import insert as mysql_insert

from src.extension import *


metadata = MetaData()


def get_sigma_rule_table() -> Table:
    return Table("sigma_rule", metadata, autoload_with=db.engine)


# ---------- 配置 ----------
_ALLOWED_EXT = (".yml", ".yaml")
_MAX_ZIP_ENTRIES = 500
_MAX_SINGLE_FILE_BYTES = 20 * 1024 * 1024     # 20MB（对齐前端）
_MAX_ZIP_TOTAL_BYTES = 80 * 1024 * 1024       # 80MB（后端更宽一点）


# ---------- 工具 ----------
def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_filestorage_bytes(file_storage) -> bytes:
    data = file_storage.read()
    try:
        file_storage.stream.seek(0)
    except Exception:
        pass
    return data

from datetime import date, datetime

def _jsonable(obj: Any) -> Any:
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_jsonable(v) for v in obj]
    return obj

from datetime import date, datetime
from typing import Any

def _jsonable(obj: Any) -> Any:
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_jsonable(v) for v in obj]
    return obj


def _decode_text(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


def _safe_zip_members(zf: zipfile.ZipFile) -> List[zipfile.ZipInfo]:
    infos: List[zipfile.ZipInfo] = []
    for info in zf.infolist():
        if info.is_dir():
            continue

        name = info.filename.replace("\\", "/")
        # zip slip 防护
        if name.startswith("/") or "../" in name or name.startswith(".."):
            raise ValueError(f"zip 内存在不安全路径：{info.filename}")

        if not name.lower().endswith(_ALLOWED_EXT):
            raise ValueError(f"zip 内包含不允许文件：{info.filename}（仅允许 .yml/.yaml）")

        infos.append(info)

    if len(infos) == 0:
        raise ValueError("zip 内没有找到任何 .yml/.yaml 文件。")
    if len(infos) > _MAX_ZIP_ENTRIES:
        raise ValueError(f"zip 内文件数量过多（>{_MAX_ZIP_ENTRIES}），已拒绝。")

    return infos


def _canonical_json_bytes(obj: Any) -> bytes:
    import json
    obj = _jsonable(obj)
    s = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return s.encode("utf-8", errors="replace")



def _normalize_rules(parsed: Any) -> List[Dict[str, Any]]:
    """
    兼容：
      1) dict: 单条规则
      2) list[dict]: 多条规则（有些人会在一个 yml 里写多文档/列表）
      3) dict 包含 rules: { rules: [ ... ] }（自定义封装）
    """
    if isinstance(parsed, list):
        return [x for x in parsed if isinstance(x, dict)]

    if isinstance(parsed, dict):
        if "rules" in parsed and isinstance(parsed["rules"], list):
            return [x for x in parsed["rules"] if isinstance(x, dict)]
        return [parsed]

    return []


def _extract_sigma_fields(rule_obj: Dict[str, Any], fallback_title: str) -> Tuple[Optional[str], str, Optional[str], Optional[str]]:
    sigma_id = rule_obj.get("id")
    title = rule_obj.get("title") or fallback_title
    description = rule_obj.get("description")
    level = rule_obj.get("level")

    if sigma_id is not None:
        sigma_id = str(sigma_id)
    title = str(title)
    if description is not None:
        description = str(description)
    if level is not None:
        level = str(level)

    return sigma_id, title, description, level


def _parse_yaml(text: str, filename_for_error: str) -> Any:
    """
    解析 YAML：
    - 支持普通 YAML
    - 支持多文档 YAML（--- 分隔），合并成 list
    """
    try:
        docs = list(yaml.safe_load_all(text))
    except Exception as e:
        raise ValueError(f"YAML 解析失败：{filename_for_error}，{str(e)}")

    # 只有一个文档时直接返回该对象
    if len(docs) == 1:
        return docs[0]

    # 多文档：返回 list
    return docs


# ---------- Service ----------
class MalSigmaUpload:
    """
    routes 调用方式（建议改名）：
      MalSigmaUpload.upload_single_yaml(request.files['file'], request.form.get('source_name'))
      MalSigmaUpload.upload_zip(request.files['file'], request.form.get('source_name'))
    """

    @staticmethod
    def upload_single_yaml(file_storage, source_name: Optional[str] = None) -> Dict[str, Any]:
        if file_storage is None:
            raise ValueError("缺少上传文件：file")

        filename = (file_storage.filename or "").strip()
        if not filename:
            raise ValueError("文件名为空")

        if not filename.lower().endswith(_ALLOWED_EXT):
            raise ValueError("文件类型不支持：仅支持 .yml / .yaml")

        raw = _read_filestorage_bytes(file_storage)
        if len(raw) > _MAX_SINGLE_FILE_BYTES:
            raise ValueError(f"文件过大：>{_MAX_SINGLE_FILE_BYTES} bytes")

        text = _decode_text(raw)
        parsed = _parse_yaml(text, filename)

        rules = _normalize_rules(parsed)
        if not rules:
            raise ValueError("YAML 中未找到可入库的 Sigma 规则对象。")

        now = datetime.now()
        table = get_sigma_rule_table()

        inserted = 0
        skipped = 0
        stored_titles: List[str] = []

        with db.engine.begin() as conn:
            for idx, rule_obj in enumerate(rules):
                rule_obj = _jsonable(rule_obj)  # 关键：入库前转换
                fallback_title = filename if len(rules) == 1 else f"{filename}#{idx+1}"
                sigma_id, title, description, level = _extract_sigma_fields(rule_obj, fallback_title)

                sha = _sha256_hex(_canonical_json_bytes(rule_obj))

                row = {
                    "sigma_id": sigma_id,
                    "title": title,
                    "description": description,
                    "rule_json": rule_obj,  # 存成 JSON（dict）
                    "level": level,
                    "source_name": source_name or "manual-upload",
                    "source_file": filename,
                    "sha256": sha,
                    "enabled": 1,
                    "created_at": now,
                    "updated_at": now,
                }

                stmt = mysql_insert(table).values(**row).prefix_with("IGNORE")
                res = conn.execute(stmt)
                if res.rowcount == 1:
                    inserted += 1
                    stored_titles.append(title)
                else:
                    skipped += 1

        return {
            "ok": True,
            "kind": "single",
            "source_name": source_name or "manual-upload",
            "filename": filename,
            "stored_count": inserted,
            "skipped_count": skipped,
            "titles_sample": stored_titles[:50],
            "file_sha256": _sha256_hex(raw),
            "created_at": now.isoformat(timespec="seconds"),
        }

    @staticmethod
    def upload_zip(file_storage, source_name: Optional[str] = None) -> Dict[str, Any]:
        if file_storage is None:
            raise ValueError("缺少上传文件：file")

        zip_name = (file_storage.filename or "").strip()
        if not zip_name:
            raise ValueError("文件名为空")

        if not zip_name.lower().endswith(".zip"):
            raise ValueError("文件类型不支持：仅支持 .zip")

        raw_zip = _read_filestorage_bytes(file_storage)
        if len(raw_zip) > _MAX_ZIP_TOTAL_BYTES:
            raise ValueError(f"zip 过大：>{_MAX_ZIP_TOTAL_BYTES} bytes")

        now = datetime.now()
        table = get_sigma_rule_table()

        inserted = 0
        skipped = 0
        stored_files: List[str] = []
        stored_titles: List[str] = []

        with zipfile.ZipFile(io.BytesIO(raw_zip)) as zf:
            members = _safe_zip_members(zf)

            with db.engine.begin() as conn:
                for info in members:
                    member_name = info.filename.replace("\\", "/")
                    data = zf.read(info)

                    if len(data) > _MAX_SINGLE_FILE_BYTES:
                        raise ValueError(f"zip 内文件过大：{member_name}")

                    text = _decode_text(data)
                    parsed = _parse_yaml(text, member_name)

                    rules = _normalize_rules(parsed)
                    if not rules:
                        raise ValueError(f"zip 内 YAML 未找到可入库规则：{member_name}")

                    file_inserted_any = False
                    for idx, rule_obj in enumerate(rules):
                        rule_obj = _jsonable(rule_obj)  #关键：入库前转换
                        fallback_title = member_name if len(rules) == 1 else f"{member_name}#{idx+1}"
                        sigma_id, title, description, level = _extract_sigma_fields(rule_obj, fallback_title)

                        sha = _sha256_hex(_canonical_json_bytes(rule_obj))

                        row = {
                            "sigma_id": sigma_id,
                            "title": title,
                            "description": description,
                            "rule_json": rule_obj,
                            "level": level,
                            "source_name": source_name or "manual-upload",
                            "source_file": member_name,
                            "sha256": sha,
                            "enabled": 1,
                            "created_at": now,
                            "updated_at": now,
                        }

                        stmt = mysql_insert(table).values(**row).prefix_with("IGNORE")
                        res = conn.execute(stmt)
                        if res.rowcount == 1:
                            inserted += 1
                            stored_titles.append(title)
                            file_inserted_any = True
                        else:
                            skipped += 1

                    if file_inserted_any:
                        stored_files.append(member_name)

        return {
            "ok": True,
            "kind": "zip",
            "source_name": source_name or "manual-upload",
            "filename": zip_name,
            "stored_count": inserted,
            "skipped_count": skipped,
            "stored_files": stored_files,
            "titles_sample": stored_titles[:50],
            "zip_sha256": _sha256_hex(raw_zip),
            "created_at": now.isoformat(timespec="seconds"),
        }
