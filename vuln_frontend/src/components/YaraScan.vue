<template>
  <div class="ui-card">
    <h2 class="ui-title">恶意代码样本静态检测（YARA）</h2>
    <div class="ui-hint">
      上传任意格式的样本文件（如 exe/dll/doc/pdf/js/zip 等），后端使用已入库的 YARA 规则进行静态匹配，
      返回命中规则与证据。为安全起见建议限制文件大小与扫描超时。
    </div>

    <div class="ui-form" style="margin-top: 14px;">
      <div class="ui-row">
        <label class="ui-label">样本标签</label>
        <input class="ui-input" v-model="sampleLabel" placeholder="可选：例如 test-1 / incident-2025-001" />
      </div>

      <div class="ui-row">
        <label class="ui-label">选择样本文件</label>
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

      <div class="ui-row">
        <label class="ui-label">规则集</label>
        <select class="ui-input" v-model="ruleSet">
          <option value="enabled">仅启用规则</option>
          <option value="all">全部规则</option>
        </select>
      </div>

      <div style="display:flex; gap: 10px; align-items:center; flex-wrap: wrap;">
        <button class="ui-btn primary" :disabled="!pickedFile || busy" @click="uploadAndScan">
          {{ busy ? '扫描中...' : '上传并扫描' }}
        </button>
        <button class="ui-btn" :disabled="busy" @click="resetAll">清空</button>
      </div>

      <div v-if="errorMsg" class="ui-error">{{ errorMsg }}</div>
      <div v-if="successMsg" class="ui-success">{{ successMsg }}</div>

      <div v-if="scanResult" style="margin-top: 10px;">
        <h3 class="ui-subtitle">扫描结果</h3>

        <div class="ui-hint" v-if="scanResult.ok">
          样本 SHA256：<b>{{ scanResult.sample_sha256 || '-' }}</b>；
          命中数量：<b>{{ (scanResult.matches || []).length }}</b>
        </div>

        <table class="ui-table" v-if="scanResult.matches && scanResult.matches.length">
          <thead>
            <tr>
              <th>规则名</th>
              <th>Tags</th>
              <th>Meta</th>
              <th>Strings 命中（可选）</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="m in scanResult.matches" :key="m.rule + '_' + (m.namespace || '')">
              <td><b>{{ m.rule }}</b><div class="ui-hint" v-if="m.namespace">ns: {{ m.namespace }}</div></td>
              <td>{{ (m.tags || []).join(', ') || '-' }}</td>
              <td>
                <div v-if="m.meta && Object.keys(m.meta).length">
                  <div v-for="(v, k) in m.meta" :key="k">
                    <span style="color:#6b7280;">{{ k }}:</span> {{ v }}
                  </div>
                </div>
                <div v-else>-</div>
              </td>
              <td>
                <div v-if="m.strings && m.strings.length">
                  <div v-for="(s, idx) in m.strings.slice(0, 8)" :key="idx">
                    <span style="color:#6b7280;">{{ s.identifier }}</span>
                    @ {{ s.offset }}
                  </div>
                  <div class="ui-hint" v-if="m.strings.length > 8">
                    仅展示前 8 条，共 {{ m.strings.length }} 条
                  </div>
                </div>
                <div v-else>-</div>
              </td>
            </tr>
          </tbody>
        </table>

        <div v-else class="ui-hint">未命中任何规则。</div>

        <div v-if="rawResp" style="margin-top: 10px;">
          <h3 class="ui-subtitle">后端原始响应</h3>
          <pre style="white-space: pre-wrap; margin:0; color:#111827;">{{ rawResp }}</pre>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
/**
 * ======================= 后端需要实现的 API（样本上传 + YARA 扫描） =======================
 *
 * Base: http://localhost:3000
 *
 * 1) 上传样本并进行 YARA 静态扫描
 *    - Method: POST
 *    - Path:   /scanSampleWithYara
 *    - Content-Type: multipart/form-data
 *    - FormData:
 *        file:        (binary) 样本文件（任意格式）
 *        label:       (string) 可选，样本标签
 *        rule_set:    (string) 可选，"enabled" | "all"（控制使用启用规则或全部规则）
 *    - 语义:
 *        后端接收样本（建议保存一份或仅临时存放），使用当前规则库中的 YARA 规则进行静态匹配。
 *        需要：
 *          - 限制文件大小（例如 <= 50MB）
 *          - 限制扫描超时（例如 5~10 秒）
 *          - 规则需预编译/缓存（避免每次 compile）
 *    - Response(建议 JSON):
 *        {
 *          ok: true,
 *          sample_id: 9001,                 // 可选
 *          sample_filename: "a.exe",
 *          sample_sha256: "....",
 *          rule_set: "enabled",
 *          matches: [
 *            {
 *              rule: "Suspicious_Strings",
 *              namespace: "default",        // 可选
 *              tags: ["malware","test"],    // 可选
 *              meta: { author: "...", description: "..." },  // 可选
 *              strings: [                   // 可选
 *                { identifier: "$a", offset: 1234 }
 *              ]
 *            }
 *          ]
 *        }
 *
 * 失败返回建议：
 *   { ok:false, code:"FILE_TOO_LARGE"|"SCAN_TIMEOUT"|"BAD_REQUEST"|"INTERNAL_ERROR", message:"..." }
 *
 * ============================================================================================
 */

import { ref } from "vue";
import axios from "axios";

const API_BASE = "http://localhost:3000";

const pickedFile = ref(null);
const sampleLabel = ref("");
const ruleSet = ref("enabled");

const busy = ref(false);
const errorMsg = ref("");
const successMsg = ref("");

const scanResult = ref(null);
const rawResp = ref("");

function resetMessages() {
  errorMsg.value = "";
  successMsg.value = "";
  rawResp.value = "";
  scanResult.value = null;
}

function resetAll() {
  pickedFile.value = null;
  sampleLabel.value = "";
  ruleSet.value = "enabled";
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

async function uploadAndScan() {
  resetMessages();

  if (!pickedFile.value) {
    errorMsg.value = "请先选择样本文件。";
    return;
  }

  try {
    busy.value = true;

    const fd = new FormData();
    fd.append("file", pickedFile.value);
    fd.append("label", sampleLabel.value || "");
    fd.append("rule_set", ruleSet.value || "enabled");

    const resp = await axios.post(`${API_BASE}/scanSampleWithYara`, fd, {
      headers: { "Content-Type": "multipart/form-data" },
    });

    scanResult.value = resp.data;
    rawResp.value = JSON.stringify(resp.data, null, 2);
    successMsg.value = "扫描完成。";
  } catch (err) {
    console.error(err);
    // 如果后端按建议返回 {ok:false,...}，可以更精细解析
    errorMsg.value = "扫描失败：请检查后端是否启动、API 是否实现，或稍后重试。";
  } finally {
    busy.value = false;
  }
}
</script>
