# src/apps/services/MalYaraUpload.py
import io
import os
import re
import uuid
import zipfile
import hashlib
import shutil
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional

import yara  # pip install yara-python

from sqlalchemy import MetaData, Table, select
from sqlalchemy.dialects.mysql import insert as mysql_insert
from src.extension import *

metadata = MetaData()


def get_yara_rule_table() -> Table:
    return Table("yara_rule", metadata, autoload_with=db.engine)


def get_yara_uncompiled_table() -> Table:
    return Table("yara_uncompiled", metadata, autoload_with=db.engine)


# --------------------------
# 配置（相对路径）
# --------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
RUNTIME_DIR = os.path.join(PROJECT_ROOT, "runtime", "yara_rules_compile_py")

_ALLOWED_EXT = (".yar", ".yara")
_MAX_ZIP_ENTRIES = 500
_MAX_SINGLE_FILE_BYTES = 20 * 1024 * 1024
_MAX_ZIP_TOTAL_BYTES = 80 * 1024 * 1024
_TEXT_DECODE_FALLBACK = "utf-8"

_RULE_HEADER_RE = re.compile(r"(?m)^\s*(?:private\s+)?rule\s+([A-Za-z_]\w*)\b")


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


def _decode_text(data: bytes) -> str:
    try:
        return data.decode(_TEXT_DECODE_FALLBACK)
    except UnicodeDecodeError:
        return data.decode(_TEXT_DECODE_FALLBACK, errors="replace")


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
            raise ValueError(f"zip 内包含不允许文件：{info.filename}（仅允许 .yar/.yara）")

        infos.append(info)

    if len(infos) == 0:
        raise ValueError("zip 内没有找到任何 .yar/.yara 文件。")
    if len(infos) > _MAX_ZIP_ENTRIES:
        raise ValueError(f"zip 内文件数量过多（>{_MAX_ZIP_ENTRIES}），已拒绝。")
    return infos


def _split_yara_rules(rule_text: str) -> List[Tuple[str, str]]:
    matches = list(_RULE_HEADER_RE.finditer(rule_text))
    if not matches:
        return [("UNKNOWN_RULE", rule_text)]

    parts: List[Tuple[str, str]] = []
    for idx, m in enumerate(matches):
        start = m.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(rule_text)
        name = m.group(1)
        single = rule_text[start:end].strip()
        parts.append((name, single))
    return parts


def _write_zip_members_to_dir(zf: zipfile.ZipFile, members: List[zipfile.ZipInfo], root_dir: str) -> None:
    """
    把 zip 内所有 yar/yara 写到 root_dir 下，保留相对路径，供 include 使用。
    """
    for info in members:
        rel = info.filename.replace("\\", "/").lstrip("/")
        disk_path = os.path.join(root_dir, rel)
        _ensure_dir(os.path.dirname(disk_path))
        with open(disk_path, "wb") as f:
            f.write(zf.read(info))


def _compile_rules_to_blob_from_source(source_text: str) -> bytes:
    """
    单文件上传：直接 compile(source=...)。
    注意：如果规则 include 其它文件，这种方式会失败（合理）。
    """
    rules = yara.compile(source=source_text)

    job_id = uuid.uuid4().hex
    job_dir = os.path.join(RUNTIME_DIR, "single_" + job_id)
    _ensure_dir(job_dir)
    out_path = os.path.join(job_dir, "compiled.yarc")

    try:
        rules.save(out_path)
        with open(out_path, "rb") as f:
            return f.read()
    finally:
        shutil.rmtree(job_dir, ignore_errors=True)


def _compile_rules_to_blob_from_filepath(filepath: str) -> bytes:
    """
    zip 上传：用 filepath 编译，支持 include（相对路径基于文件所在目录）。
    """
    rules = yara.compile(filepath=filepath)

    job_id = uuid.uuid4().hex
    job_dir = os.path.join(RUNTIME_DIR, "file_" + job_id)
    _ensure_dir(job_dir)
    out_path = os.path.join(job_dir, "compiled.yarc")

    try:
        rules.save(out_path)
        with open(out_path, "rb") as f:
            return f.read()
    finally:
        shutil.rmtree(job_dir, ignore_errors=True)


def _get_or_create_compiled_rule_id(
    conn,
    yara_rule_table: Table,
    source_name: str,
    source_file: str,
    compiled_blob: bytes,
    now: datetime,
) -> int:
    """
    以 compiled_sha256 去重：
      - 已存在：复用 id
      - 不存在：插入并拿到 id
    """
    compiled_sha = _sha256_hex(compiled_blob)

    # 先查
    stmt_sel = select(yara_rule_table.c.id).where(yara_rule_table.c.compiled_sha256 == compiled_sha)
    row = conn.execute(stmt_sel).mappings().first()
    if row and row.get("id"):
        return int(row["id"])

    # 不存在则插入
    row_ins = {
        "source_name": source_name,
        "source_file": source_file,
        "compiled_rule": compiled_blob,
        "compiled_sha256": compiled_sha,
        "compiled_at": now,
        "enabled": 1,
        "created_at": now,
        "updated_at": now,
    }
    stmt_ins = mysql_insert(yara_rule_table).values(**row_ins)
    res = conn.execute(stmt_ins)
    # MySQL insert 返回 lastrowid 可用
    new_id = res.lastrowid
    if not new_id:
        # 极低概率并发：刚好有人插入了同 sha，再查一次
        row2 = conn.execute(stmt_sel).mappings().first()
        if row2 and row2.get("id"):
            return int(row2["id"])
        raise ValueError("写入编译规则失败：无法获取 id")

    return int(new_id)


class MalYaraUpload:

    @staticmethod
    def upload_single(file_storage, source_name: Optional[str] = None) -> Dict[str, Any]:
        if file_storage is None:
            raise ValueError("缺少上传文件：file")

        filename = (file_storage.filename or "").strip()
        if not filename:
            raise ValueError("文件名为空")
        if not filename.lower().endswith(_ALLOWED_EXT):
            raise ValueError("文件类型不支持：仅支持 .yar / .yara")

        raw = _read_filestorage_bytes(file_storage)
        if len(raw) > _MAX_SINGLE_FILE_BYTES:
            raise ValueError(f"文件过大：>{_MAX_SINGLE_FILE_BYTES} bytes")

        rule_text_full = _decode_text(raw)
        rules = _split_yara_rules(rule_text_full)

        # 编译（单文件：不支持 include 依赖，失败即报错）
        try:
            compiled_blob = _compile_rules_to_blob_from_source(rule_text_full)
        except yara.SyntaxError as e:
            raise ValueError(f"YARA_COMPILE_FAILED: {str(e)}")
        except yara.Error as e:
            raise ValueError(f"YARA_COMPILE_FAILED: {str(e)}")

        now = datetime.now()
        source_name2 = source_name or "manual-upload"
        yara_rule_table = get_yara_rule_table()
        yara_un_table = get_yara_uncompiled_table()

        inserted = 0
        skipped = 0
        stored_rule_names: List[str] = []

        with db.engine.begin() as conn:
            # 1) 编译产物入 yara_rule（去重复用）
            compiled_rule_id = _get_or_create_compiled_rule_id(
                conn,
                yara_rule_table,
                source_name=source_name2,
                source_file=filename,
                compiled_blob=compiled_blob,
                now=now,
            )

            # 2) 原始规则入 yara_uncompiled（按 rule_text sha 去重）
            for rule_name, rule_text in rules:
                sha = _sha256_hex(rule_text.encode("utf-8", errors="replace"))
                row = {
                    "rule_name": rule_name,
                    "rule_text": rule_text,
                    "source_name": source_name2,
                    "source_file": filename,
                    "sha256": sha,
                    "compiled_rule_id": compiled_rule_id,  # ✅ 外键
                    "created_at": now,
                    "updated_at": now,
                }
                stmt = mysql_insert(yara_un_table).values(**row).prefix_with("IGNORE")
                res = conn.execute(stmt)
                if res.rowcount == 1:
                    inserted += 1
                    stored_rule_names.append(rule_name)
                else:
                    skipped += 1

        return {
            "ok": True,
            "kind": "single",
            "source_name": source_name2,
            "filename": filename,
            "stored_count": inserted,
            "skipped_count": skipped,
            "rule_names": stored_rule_names,
            "file_sha256": _sha256_hex(raw),
            "created_at": now.isoformat(timespec="seconds"),
        }

    @staticmethod
    def upload_zip(file_storage, source_name: Optional[str] = None) -> Dict[str, Any]:
        try:
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
            source_name2 = source_name or "manual-upload"

            yara_rule_table = get_yara_rule_table()
            yara_un_table = get_yara_uncompiled_table()

            inserted = 0
            skipped = 0
            stored_files: List[str] = []
            stored_rule_names: List[str] = []

            # 一个 job_dir 用于落盘 zip（支持 include）
            job_id = uuid.uuid4().hex
            job_dir = os.path.join(RUNTIME_DIR, "zip_" + job_id)
            _ensure_dir(job_dir)

            try:
                with zipfile.ZipFile(io.BytesIO(raw_zip)) as zf:
                    members = _safe_zip_members(zf)
                    _write_zip_members_to_dir(zf, members, job_dir)

                    with db.engine.begin() as conn:
                        for info in members:
                            member_name = info.filename.replace("\\", "/").lstrip("/")
                            disk_path = os.path.join(job_dir, member_name)

                            if os.path.getsize(disk_path) > _MAX_SINGLE_FILE_BYTES:
                                raise ValueError(f"zip 内文件过大：{member_name}")

                            with open(disk_path, "rb") as f:
                                text = _decode_text(f.read())

                            rules = _split_yara_rules(text)

                            # 编译：用 filepath（支持 include）
                            try:
                                compiled_blob = _compile_rules_to_blob_from_filepath(disk_path)
                            except yara.SyntaxError as e:
                                raise ValueError(f"YARA_COMPILE_FAILED: {member_name}: {str(e)}")
                            except yara.Error as e:
                                raise ValueError(f"YARA_COMPILE_FAILED: {member_name}: {str(e)}")

                            # 1) 编译产物入 yara_rule（去重复用）
                            compiled_rule_id = _get_or_create_compiled_rule_id(
                                conn,
                                yara_rule_table,
                                source_name=source_name2,
                                source_file=member_name,
                                compiled_blob=compiled_blob,
                                now=now,
                            )

                            # 2) 原始规则入 yara_uncompiled（按 rule_text sha 去重）
                            file_inserted_any = False
                            for rule_name, rule_text in rules:
                                sha = _sha256_hex(rule_text.encode("utf-8", errors="replace"))
                                row = {
                                    "rule_name": rule_name,
                                    "rule_text": rule_text,
                                    "source_name": source_name2,
                                    "source_file": member_name,
                                    "sha256": sha,
                                    "compiled_rule_id": compiled_rule_id,
                                    "created_at": now,
                                    "updated_at": now,
                                }
                                stmt = mysql_insert(yara_un_table).values(**row).prefix_with("IGNORE")
                                res = conn.execute(stmt)
                                if res.rowcount == 1:
                                    inserted += 1
                                    stored_rule_names.append(rule_name)
                                    file_inserted_any = True
                                else:
                                    skipped += 1

                            if file_inserted_any:
                                stored_files.append(member_name)

            finally:
                shutil.rmtree(job_dir, ignore_errors=True)

            return {
                "ok": True,
                "kind": "zip",
                "source_name": source_name2,
                "filename": zip_name,
                "stored_count": inserted,
                "skipped_count": skipped,
                "stored_files": stored_files,
                "rule_names_sample": stored_rule_names[:50],
                "zip_sha256": _sha256_hex(raw_zip),
                "created_at": now.isoformat(timespec="seconds"),
            }

        except Exception as e:
            raise ValueError(f"[upload_zip] {str(e)}")
