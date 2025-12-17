#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import json
import time
import hashlib
import argparse
import tempfile
import zipfile
import tarfile
from pathlib import Path
from typing import Dict, Any, Iterable, List, Tuple, Optional

import requests


# ---------------------------
# 可按需调整的默认参数
# ---------------------------
DEFAULT_RULE_SET = "enabled"          # enabled | all
DEFAULT_TIMEOUT = (10, 60)            # (connect_timeout, read_timeout)
MAX_UPLOAD_BYTES = 50 * 1024 * 1024   # 与后端 MAX_SAMPLE_BYTES 对齐（50MB）


# ---------------------------
# 工具函数
# ---------------------------
def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def safe_result_filename(rel_path: str, suffix: str = "_testres.json", max_len: int = 180) -> str:
    r"""
    把相对路径转成安全文件名：将 / \ 替换为 __，去掉不安全字符，并控制长度。
    为避免同名冲突，追加一个短 hash。
    """
    rel_path = rel_path.replace("\\", "/")
    base = rel_path.replace("/", "__")
    base = re.sub(r"[^0-9A-Za-z\u4e00-\u9fff\.\-_]+", "_", base)

    # 避免过长：截断 + hash
    digest = hashlib.sha1(rel_path.encode("utf-8", errors="ignore")).hexdigest()[:10]
    name = f"{base}__{digest}"

    if len(name) > max_len:
        name = name[:max_len] + f"__{digest}"

    return name + suffix


def is_archive(path: Path) -> bool:
    lower = path.name.lower()
    return lower.endswith(".zip") or lower.endswith(".tar") or lower.endswith(".tar.gz") or lower.endswith(".tgz")


def iter_files_recursive(root: Path) -> Iterable[Path]:
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            yield Path(dirpath) / fn


def extract_archive_to_temp(archive_path: Path, temp_dir: Path) -> List[Path]:
    """
    解压 zip/tar/tar.gz/tgz 到 temp_dir，返回解压出的文件列表（仅文件，不含目录）
    """
    extracted_files: List[Path] = []
    name = archive_path.name.lower()

    if name.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as z:
            z.extractall(temp_dir)
    elif name.endswith(".tar") or name.endswith(".tar.gz") or name.endswith(".tgz"):
        mode = "r:gz" if (name.endswith(".tar.gz") or name.endswith(".tgz")) else "r:"
        with tarfile.open(archive_path, mode) as t:
            t.extractall(temp_dir)
    else:
        return extracted_files

    for p in iter_files_recursive(temp_dir):
        if p.is_file():
            extracted_files.append(p)

    return extracted_files


def call_yara_scan_api(
    api_url: str,
    file_path: Path,
    rule_set: str = DEFAULT_RULE_SET,
    label: str = "",
    timeout: Tuple[int, int] = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """
    调用后端 /scanSampleWithYara
    """
    with file_path.open("rb") as f:
        files = {
            "file": (file_path.name, f, "application/octet-stream")
        }
        data = {
            "label": label,
            "rule_set": rule_set
        }
        r = requests.post(api_url, files=files, data=data, timeout=timeout)
    # 兼容非 200 的 JSON 返回
    try:
        payload = r.json()
    except Exception:
        payload = {"ok": False, "code": "NON_JSON_RESPONSE", "message": r.text[:2000]}

    payload["_http_status"] = r.status_code
    return payload


def parse_scan_result(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    从后端返回中提取：命中规则数、命中规则名等
    """
    ok = bool(payload.get("ok"))
    matches = payload.get("matches") if isinstance(payload.get("matches"), list) else []
    rule_names = []
    for m in matches:
        if isinstance(m, dict) and m.get("rule"):
            rule_names.append(m["rule"])

    uniq_rule_names = sorted(set(rule_names))
    return {
        "ok": ok,
        "code": payload.get("code"),
        "message": payload.get("message"),
        "http_status": payload.get("_http_status"),
        "sample_filename": payload.get("sample_filename"),
        "sample_sha256_from_server": payload.get("sample_sha256"),
        "rule_set": payload.get("rule_set"),
        "hit_rule_count": len(matches),
        "hit_rule_names": uniq_rule_names,
        # 如你想保留原始 matches，可开启下面这行：
        "matches": matches,
        # 调试信息（可选，可能很长，建议裁剪）
        "engine_stderr_tail": (payload.get("engine_stderr") or "")[-2000:],
        "engine_stdout_tail": (payload.get("engine_stdout") or "")[-2000:],
    }


def write_result_json(out_dir: Path, rel_path: str, result: Dict[str, Any]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    out_name = safe_result_filename(rel_path)
    out_path = out_dir / out_name
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    return out_path


# ---------------------------
# 主流程
# ---------------------------
def scan_one_file(
    api_url: str,
    root_dir: Path,
    file_path: Path,
    out_dir: Path,
    rule_set: str,
    timeout: Tuple[int, int],
    label_prefix: str = "",
) -> Dict[str, Any]:
    rel_path = str(file_path.relative_to(root_dir)).replace("\\", "/")

    # 文件大小预检（跟后端 50MB 限制对齐）
    try:
        size = file_path.stat().st_size
    except Exception as e:
        result = {
            "ok": False,
            "code": "STAT_FAILED",
            "message": str(e),
            "rel_path": rel_path,
        }
        write_result_json(out_dir, rel_path, result)
        return result

    if size > MAX_UPLOAD_BYTES:
        result = {
            "ok": False,
            "code": "SKIP_TOO_LARGE",
            "message": f"skip: file size {size} > {MAX_UPLOAD_BYTES} (backend limit)",
            "rel_path": rel_path,
            "size": size,
        }
        write_result_json(out_dir, rel_path, result)
        return result

    # 可选：本地算 sha256（大目录会慢；你想要就保留）
    local_sha256 = None
    try:
        local_sha256 = sha256_file(file_path)
    except Exception:
        pass

    label = f"{label_prefix}{rel_path}" if label_prefix else rel_path

    payload = call_yara_scan_api(
        api_url=api_url,
        file_path=file_path,
        rule_set=rule_set,
        label=label,
        timeout=timeout,
    )

    parsed = parse_scan_result(payload)
    parsed.update({
        "rel_path": rel_path,
        "abs_path": str(file_path),
        "size": size,
        "local_sha256": local_sha256,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    })

    write_result_json(out_dir, rel_path, parsed)
    return parsed


def main():
    parser = argparse.ArgumentParser(description="Batch YARA scan client (call backend /scanSampleWithYara).")
    parser.add_argument("folder", help="要扫描的文件夹绝对路径")
    parser.add_argument("--api", required=True, help="后端接口URL，例如 http://127.0.0.1:5000/scanSampleWithYara")
    parser.add_argument("--rule-set", default=DEFAULT_RULE_SET, choices=["enabled", "all"], help="规则集：enabled|all")
    parser.add_argument("--connect-timeout", type=int, default=DEFAULT_TIMEOUT[0])
    parser.add_argument("--read-timeout", type=int, default=DEFAULT_TIMEOUT[1])
    parser.add_argument("--no-archives", action="store_true", help="不处理压缩包（zip/tar/tgz）")
    parser.add_argument("--label-prefix", default="", help="label 前缀（可选）")
    args = parser.parse_args()

    root_dir = Path(args.folder).expanduser().resolve()
    if not root_dir.exists() or not root_dir.is_dir():
        print(f"[!] folder not found or not a directory: {root_dir}")
        sys.exit(2)

    # 输出目录：与文件夹同级，名为 <文件夹名>_testres
    out_dir = root_dir.parent / f"{root_dir.name}_testres"
    out_dir.mkdir(parents=True, exist_ok=True)

    timeout = (args.connect_timeout, args.read_timeout)

    summary = {
        "root_dir": str(root_dir),
        "api": args.api,
        "rule_set": args.rule_set,
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_files_seen": 0,
        "total_scanned": 0,
        "total_ok": 0,
        "total_hit_files": 0,
        "total_skipped_too_large": 0,
        "total_errors": 0,
        "hit_rule_counter": {},  # rule -> count of files hit
    }

    def bump_rule_counter(hit_rules: List[str]):
        c = summary["hit_rule_counter"]
        for r in hit_rules:
            c[r] = int(c.get(r, 0)) + 1

    # 遍历
    for p in iter_files_recursive(root_dir):
        if not p.is_file():
            continue

        summary["total_files_seen"] += 1

        # 处理压缩包：解压 -> 扫描解压文件 -> 立刻删除临时解压文件
        if (not args.no_archives) and is_archive(p):
            rel_arch = str(p.relative_to(root_dir)).replace("\\", "/")
            # 给压缩包也写一个“容器结果”文件（可选）
            container_note = {
                "ok": True,
                "code": "ARCHIVE_CONTAINER",
                "message": f"archive detected, will extract+scan then delete extracted files: {p.name}",
                "rel_path": rel_arch,
                "abs_path": str(p),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            write_result_json(out_dir, rel_arch + ".__archive__", container_note)

            with tempfile.TemporaryDirectory(prefix="yara_extract_") as td:
                temp_dir = Path(td)
                try:
                    extracted = extract_archive_to_temp(p, temp_dir)
                except Exception as e:
                    err = {
                        "ok": False,
                        "code": "ARCHIVE_EXTRACT_FAILED",
                        "message": str(e),
                        "rel_path": rel_arch,
                        "abs_path": str(p),
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    write_result_json(out_dir, rel_arch + ".__archive__", err)
                    summary["total_errors"] += 1
                    continue

                # 扫描解压出来的文件（注意：这些文件不在 root_dir 下，所以 rel_path 用 “压缩包相对路径::解压相对路径”）
                for ep in extracted:
                    summary["total_scanned"] += 1
                    fake_rel = rel_arch + "::" + str(ep.relative_to(temp_dir)).replace("\\", "/")

                    # 尺寸检查（解压文件也可能很大）
                    try:
                        if ep.stat().st_size > MAX_UPLOAD_BYTES:
                            result = {
                                "ok": False,
                                "code": "SKIP_TOO_LARGE",
                                "message": f"skip: file size {ep.stat().st_size} > {MAX_UPLOAD_BYTES} (backend limit)",
                                "rel_path": fake_rel,
                                "abs_path": str(ep),
                                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                            }
                            write_result_json(out_dir, fake_rel, result)
                            summary["total_skipped_too_large"] += 1
                            continue
                    except Exception:
                        pass

                    payload = call_yara_scan_api(
                        api_url=args.api,
                        file_path=ep,
                        rule_set=args.rule_set,
                        label=(args.label_prefix + fake_rel) if args.label_prefix else fake_rel,
                        timeout=timeout,
                    )
                    parsed = parse_scan_result(payload)
                    parsed.update({
                        "rel_path": fake_rel,
                        "abs_path": str(ep),
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    })
                    write_result_json(out_dir, fake_rel, parsed)

                    if parsed.get("ok"):
                        summary["total_ok"] += 1
                        if parsed.get("hit_rule_count", 0) > 0:
                            summary["total_hit_files"] += 1
                            bump_rule_counter(parsed.get("hit_rule_names", []))
                    else:
                        if parsed.get("code") == "FILE_TOO_LARGE" or parsed.get("code") == "SKIP_TOO_LARGE":
                            summary["total_skipped_too_large"] += 1
                        else:
                            summary["total_errors"] += 1

            # TemporaryDirectory 会自动删除解压出来的所有文件：满足“扫描完立即删除”
            continue

        # 普通文件扫描
        summary["total_scanned"] += 1
        r = scan_one_file(
            api_url=args.api,
            root_dir=root_dir,
            file_path=p,
            out_dir=out_dir,
            rule_set=args.rule_set,
            timeout=timeout,
            label_prefix=args.label_prefix,
        )

        if r.get("ok"):
            summary["total_ok"] += 1
            if r.get("hit_rule_count", 0) > 0:
                summary["total_hit_files"] += 1
                bump_rule_counter(r.get("hit_rule_names", []))
        else:
            if r.get("code") == "SKIP_TOO_LARGE" or r.get("code") == "FILE_TOO_LARGE":
                summary["total_skipped_too_large"] += 1
            else:
                summary["total_errors"] += 1

    summary["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

    # 写总览
    summary_path = out_dir / f"{root_dir.name}_testres_summary.json"
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"[OK] Done. Results in: {out_dir}")
    print(f"[OK] Summary: {summary_path}")


if __name__ == "__main__":
    main()
