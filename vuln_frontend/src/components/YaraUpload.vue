<template>
  <div class="ui-card">
    <h2 class="ui-title">YARA 规则导入</h2>
    <div class="ui-hint">
      支持上传 <b>.yar</b> / <b>.yara</b> / <b>.zip</b>（zip 内只允许包含 yar/yara 文件）。
<!--      前端会先校验格式，校验通过后再上传到后端 http://localhost:3000。-->
    </div>

    <div class="ui-form" style="margin-top: 14px;">
      <div class="ui-row">
        <label class="ui-label">规则源名称</label>
        <input class="ui-input" v-model="sourceName" placeholder="例如：manual-upload / sigma-yara-pack" />
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
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in zipPreview" :key="row.path">
              <td>{{ row.path }}</td>
              <td>{{ prettySize(row.size) }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-if="serverResp" style="margin-top: 10px;">
        <h3 class="ui-subtitle">后端响应</h3>
        <pre style="white-space: pre-wrap; margin:0; color: #111827;">{{ serverResp }}</pre>
      </div>
    </div>
  </div>
</template>

<script setup>
/**
 * ======================= 后端需要实现的 API =======================
 *
 * Base: http://localhost:3000
 *
 * 1) 上传单个 YARA 规则文件（.yar / .yara）
 *    - Method: POST
 *    - Path:   /uploadYaraRule
 *    - Content-Type: multipart/form-data
 *    - FormData:
 *        file:  (binary) 规则文件本体
 *        source_name: (string) 可选，规则来源标签（例如 manual-upload）
 *    - 语义:
 *        后端接收单个 yara 文件并写入数据库（或落盘+写元信息），返回写入结果。
 *    - Response(建议 JSON):
 *        { ok: true, kind: "single", rule_pack_id: 123, stored_count: 1, filename: "xxx.yar", sha256: "...", created_at: "..." }
 *
 * 2) 上传 zip 规则包（zip 内只允许包含 .yar/.yara 文件）
 *    - Method: POST
 *    - Path:   /uploadYaraRuleZip
 *    - Content-Type: multipart/form-data
 *    - FormData:
 *        file:  (binary) zip 文件本体
 *        source_name: (string) 可选
 *    - 语义:
 *        后端接收 zip，后端也应再次校验 zip 内容安全（不要只信前端），逐个提取 yara 规则写入数据库。
 *    - Response(建议 JSON):
 *        { ok: true, kind: "zip", rule_pack_id: 456, stored_count: 27, filenames: ["a.yar","b.yara"], sha256: "...", created_at: "..." }
 *
 * 说明：前端会做格式校验，但后端必须做二次校验（安全）。
 * ==============================================================================================
 */

import { ref } from "vue";
import axios from "axios";
import JSZip from "jszip";

const API_BASE = "http://localhost:3000";

const sourceName = ref("manual-upload");

const pickedFile = ref(null);
const busy = ref(false);
const errorMsg = ref("");
const successMsg = ref("");
const serverResp = ref("");
const zipPreview = ref([]);

const MAX_FILE_SIZE_BYTES = 20 * 1024 * 1024; // 20MB
const MAX_ZIP_ENTRIES = 500;                  // 防止 zip 炸弹/超多文件
const ALLOWED_RULE_EXTS = [".yar", ".yara"];

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
  const f = e?.target?.files?.[0] || null;
  pickedFile.value = f;
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

function isAllowedRuleFileName(name) {
  const n = lowerName(name);
  return ALLOWED_RULE_EXTS.some(ext => n.endsWith(ext));
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

  const name = f.name || "";
  const n = lowerName(name);

  try {
    busy.value = true;

    if (isAllowedRuleFileName(n)) {
      // 单文件：直接上传
      await uploadSingleRule(f);
      return;
    }

    if (isZipFileName(n)) {
      // zip：前端先解包检查
      const entries = await inspectZipAndBuildPreview(f);
      zipPreview.value = entries;

      await uploadZipPack(f);
      return;
    }

    errorMsg.value = "文件类型不支持：仅支持 .yar / .yara / .zip。";
  } catch (err) {
    console.error(err);
    errorMsg.value = err?.message || "处理失败，请稍后重试。";
  } finally {
    busy.value = false;
  }
}

async function inspectZipAndBuildPreview(file) {
  // 读取 zip 二进制
  const arrayBuf = await file.arrayBuffer();
  const zip = await JSZip.loadAsync(arrayBuf);

  const entries = [];
  let entryCount = 0;

  // JSZip.files 是一个 map：path -> entry
  for (const [path, entry] of Object.entries(zip.files)) {
    // entry.dir 表示目录
    if (entry.dir) continue;

    entryCount++;
    if (entryCount > MAX_ZIP_ENTRIES) {
      throw new Error(`zip 内文件数过多（>${MAX_ZIP_ENTRIES}），已拒绝。`);
    }

    // 不允许非 yar/yara
    if (!isAllowedRuleFileName(path)) {
      throw new Error(`zip 内包含不允许的文件：${path}（仅允许 .yar/.yara）`);
    }

    // 获取大小：需要读取一次
    const blob = await entry.async("blob");
    entries.push({ path, size: blob.size });
  }

  if (entries.length === 0) {
    throw new Error("zip 内没有找到任何 .yar/.yara 文件。");
  }

  // 按文件名排序
  entries.sort((a, b) => a.path.localeCompare(b.path));
  return entries;
}

async function uploadSingleRule(file) {
  const fd = new FormData();
  fd.append("file", file);
  fd.append("source_name", sourceName.value || "");

  const resp = await axios.post(`${API_BASE}/uploadYaraRule`, fd, {
    headers: { "Content-Type": "multipart/form-data" },
  });

  successMsg.value = "上传成功（单文件）。";
  serverResp.value = JSON.stringify(resp.data, null, 2);
}

async function uploadZipPack(file) {
  const fd = new FormData();
  fd.append("file", file);
  fd.append("source_name", sourceName.value || "");

  const resp = await axios.post(`${API_BASE}/uploadYaraRuleZip`, fd, {
    headers: { "Content-Type": "multipart/form-data" },
  });

  successMsg.value = "上传成功（zip 规则包）。";
  serverResp.value = JSON.stringify(resp.data, null, 2);
}
</script>
