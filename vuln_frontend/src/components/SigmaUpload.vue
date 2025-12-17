<template>
  <div class="ui-card">
    <h2 class="ui-title">Sigma 规则导入（YAML）</h2>
    <div class="ui-hint">
      支持上传 <b>.yml</b> 或 <b>.zip</b>（zip 内只允许包含 yml 文件）。
      前端会先校验：扩展名、zip 内容、yaml 合法性；校验通过后再上传到后端。
    </div>

    <div class="ui-form" style="margin-top: 14px;">
      <div class="ui-row">
        <label class="ui-label">规则源名称</label>
        <input class="ui-input" v-model="sourceName" placeholder="例如：manual-upload / sigma-pack" />
      </div>

      <div class="ui-row">
        <label class="ui-label">选择文件</label>
<!--        <input class="ui-input" type="file" @change="onFileChange" />-->
        <div class="ui-file">
  <label class="ui-btn primary">
    选择文件
    <input type="file" @change="onFileChange" />
  </label>

  <span v-if="pickedFile" class="ui-file-name">
    已选择：{{ pickedFile.name }}（{{ prettySize(pickedFile.size) }}）
  </span>
  <span v-else class="ui-file-empty">
    未选择文件
  </span>
</div>

      </div>

      <div v-if="pickedFile" class="ui-hint">
        已选择：<b>{{ pickedFile.name }}</b>（{{ prettySize(pickedFile.size) }}）
      </div>

      <div style="display:flex; gap: 10px; align-items:center; flex-wrap: wrap;">
        <button class="ui-btn primary" :disabled="!pickedFile || busy" @click="validateAndUpload">
          {{ busy ? '处理中...' : '校验并上传' }}
        </button>
        <button class="ui-btn" :disabled="busy" @click="resetAll">清空</button>
      </div>

      <div v-if="errorMsg" class="ui-error">{{ errorMsg }}</div>
      <div v-if="successMsg" class="ui-success">{{ successMsg }}</div>

      <div v-if="zipPreview.length" style="margin-top: 10px;">
        <h3 class="ui-subtitle">Zip 内容预览（校验通过后才会展示）</h3>
        <table class="ui-table">
          <thead>
            <tr>
              <th>文件名</th>
              <th>大小</th>
              <th>yml 校验</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in zipPreview" :key="row.path">
              <td>{{ row.path }}</td>
              <td>{{ prettySize(row.size) }}</td>
              <td>{{ row.jsonOk ? 'OK' : '失败' }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-if="serverResp" style="margin-top: 10px;">
        <h3 class="ui-subtitle">后端响应</h3>
        <pre style="white-space: pre-wrap; margin:0; color:#111827;">{{ serverResp }}</pre>
      </div>
    </div>
  </div>
</template>

<script setup>
/**
 * ======================= 后端 API 设计规范（建议你以后跨页面复用） =======================
 *
 * Base: http://localhost:3000
 *
 * 通用约定：
 * - 成功返回：HTTP 200，JSON { ok: true, ... }
 * - 失败返回：建议 HTTP 4xx/5xx，JSON { ok: false, code: "SOME_CODE", message: "人类可读错误", detail?: any }
 * - 上传使用 multipart/form-data
 * - 后端必须做二次校验（不要只信前端）：
 *     * 文件后缀、MIME 只能做参考
 *     * zip 需要限制文件数/解压后总大小（防 zip bomb）
 *     * json 需要 parse 校验
 *
 * 本页面需要实现的 API（Sigma 规则 JSON）：
 *
 * 1) 上传单个 Sigma JSON 文件（.json）
 *    - Method: POST
 *    - Path:   /uploadSigmaRuleJson
 *    - Content-Type: multipart/form-data
 *    - FormData:
 *        file:        (binary) json 文件
 *        source_name: (string) 可选，来源标签
 *    - 语义:
 *        后端接收单个 JSON（Sigma 规则或规则集合），校验 JSON 合法性，写入数据库（或落盘+元信息入库）。
 *    - Response(建议):
 *        {
 *          ok: true,
 *          kind: "single",
 *          rule_pack_id: 1001,
 *          stored_count: 1,
 *          filename: "rule.json",
 *          sha256: "...",
 *          created_at: "..."
 *        }
 *
 * 2) 上传 zip Sigma JSON 规则包（zip 内只允许 json）
 *    - Method: POST
 *    - Path:   /uploadSigmaRuleZip
 *    - Content-Type: multipart/form-data
 *    - FormData:
 *        file:        (binary) zip 文件
 *        source_name: (string) 可选
 *    - 语义:
 *        后端接收 zip，二次校验 zip 结构与内容：
 *          - 仅允许 .json 文件（可有目录）
 *          - 每个 json 都应可被解析（JSON.parse 等价校验）
 *        然后逐个写入数据库（或存包+索引），并返回写入统计。
 *    - Response(建议):
 *        {
 *          ok: true,
 *          kind: "zip",
 *          rule_pack_id: 1002,
 *          stored_count: 27,
 *          filenames: ["a.json","b.json"],
 *          sha256: "...",
 *          created_at: "..."
 *        }
 *
 * ============================================================================================
 */

import { ref } from "vue";
import axios from "axios";
import JSZip from "jszip";
import YAML from "js-yaml";


const API_BASE = "http://localhost:3000";

const sourceName = ref("manual-upload");

const pickedFile = ref(null);
const busy = ref(false);
const errorMsg = ref("");
const successMsg = ref("");
const serverResp = ref("");
const zipPreview = ref([]);

// 限制参数（可按需调整）
const MAX_FILE_SIZE_BYTES = 20 * 1024 * 1024; // 20MB
const MAX_ZIP_ENTRIES = 500;
const ALLOWED_EXTS = [".yml", ".yaml"];
// const ALLOWED_EXTS = [".json"];

function resetMessages() {
  errorMsg.value = "";
  successMsg.value = "";
  serverResp.value = "";
  zipPreview.value = [];
}

function resetAll() {
  pickedFile.value = null;
  resetMessages();
}

function onFileChange(e) {
  resetMessages();
  pickedFile.value = e?.target?.files?.[0] || null;
}

function prettySize(bytes) {
  if (typeof bytes !== "number") return "-";
  const units = ["B", "KB", "MB", "GB"];
  let n = bytes;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(i === 0 ? 0 : 2)} ${units[i]}`;
}

function lowerName(name) {
  return (name || "").toLowerCase();
}

function isAllowedJsonFileName(name) {
  const n = lowerName(name);
  return ALLOWED_EXTS.some(ext => n.endsWith(ext));
}

function isZipFileName(name) {
  return lowerName(name).endsWith(".zip");
}

async function validateAndUpload() {
  resetMessages();
  serverResp.value = "";

  if (!pickedFile.value) {
    errorMsg.value = "请先选择文件。";
    return;
  }

  const f = pickedFile.value;

  if (f.size > MAX_FILE_SIZE_BYTES) {
    errorMsg.value = `文件过大：${prettySize(f.size)}，请小于 ${prettySize(MAX_FILE_SIZE_BYTES)}。`;
    return;
  }

  const filename = f.name || "";
  const n = lowerName(filename);

  try {
    busy.value = true;

    if (isAllowedJsonFileName(n)) {
      // 单 json：先 parse 校验
      await validateJsonFile(f);
      await uploadSingleJson(f);
      return;
    }

    if (isZipFileName(n)) {
      // zip：解包检查 + 每个 json parse
      const entries = await inspectZipAndBuildPreview(f);
      zipPreview.value = entries;

      await uploadZipPack(f);
      return;
    }

    errorMsg.value = "文件类型不支持：仅支持 .json / .zip。";
  } catch (err) {
    console.error(err);
    errorMsg.value = err?.message || "处理失败，请稍后重试。";
  } finally {
    busy.value = false;
  }
}

async function validateJsonFile(file) {
  const text = await file.text();
  try {
    YAML.load(text);
    // JSON.parse(text);
  } catch {
    throw new Error("JSON 文件格式错误：无法解析（请确认是合法 JSON）。");
  }
}

async function inspectZipAndBuildPreview(file) {
  const arrayBuf = await file.arrayBuffer();
  const zip = await JSZip.loadAsync(arrayBuf);

  const entries = [];
  let entryCount = 0;

  for (const [path, entry] of Object.entries(zip.files)) {
    if (entry.dir) continue;

    entryCount++;
    if (entryCount > MAX_ZIP_ENTRIES) {
      throw new Error(`zip 内文件数过多（>${MAX_ZIP_ENTRIES}），已拒绝。`);
    }

    if (!isAllowedJsonFileName(path)) {
      throw new Error(`zip 内包含不允许的文件：${path}（仅允许 .json）`);
    }

    // 读取并校验 JSON
    const text = await entry.async("text");
    let jsonOk = true;
    try {
      YAML.load(text);
      // JSON.parse(text);
    } catch {
      jsonOk = false;
    }
    if (!jsonOk) {
      throw new Error(`zip 内 JSON 无法解析：${path}`);
    }

    // 获取大小用于预览
    const blob = await entry.async("blob");
    entries.push({ path, size: blob.size, jsonOk: true });
  }

  if (entries.length === 0) {
    throw new Error("zip 内没有找到任何 .json 文件。");
  }

  entries.sort((a, b) => a.path.localeCompare(b.path));
  return entries;
}

async function uploadSingleJson(file) {
  const fd = new FormData();
  fd.append("file", file);
  fd.append("source_name", sourceName.value || "");

  const resp = await axios.post(`${API_BASE}/uploadSigmaRuleYaml`, fd, {
    headers: { "Content-Type": "multipart/form-data" },
  });

  successMsg.value = "上传成功（单 JSON 文件）。";
  serverResp.value = JSON.stringify(resp.data, null, 2);
}

async function uploadZipPack(file) {
  const fd = new FormData();
  fd.append("file", file);
  fd.append("source_name", sourceName.value || "");

  const resp = await axios.post(`${API_BASE}/uploadSigmaRuleZip`, fd, {
    headers: { "Content-Type": "multipart/form-data" },
  });

  successMsg.value = "上传成功（zip 规则包）。";
  serverResp.value = JSON.stringify(resp.data, null, 2);
}
</script>
