<template>
  <div class="ui-card">
    <h2 class="ui-title">EVTX 日志检测（Sigma）</h2>
    <div class="ui-hint">
      上传 Windows <b>.evtx</b> 事件日志文件，后端解析事件并用 Sigma 规则进行检测，返回命中告警与证据。
      前端会校验扩展名，仅允许上传 .evtx。
    </div>

    <div class="ui-form" style="margin-top: 14px;">
      <div class="ui-row">
        <label class="ui-label">日志标签</label>
        <input class="ui-input" v-model="logLabel" placeholder="可选：例如 host01-security / incident-2025-evtx" />
      </div>

      <div class="ui-row">
        <label class="ui-label">选择 EVTX 文件</label>
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

      <div class="ui-row">
        <label class="ui-label">结果返回级别</label>
        <select class="ui-input" v-model="returnLevel">
          <option value="summary">摘要（推荐）</option>
          <option value="with_events">包含命中事件（可能很大）</option>
        </select>
      </div>

      <div style="display:flex; gap: 10px; align-items:center; flex-wrap: wrap;">
        <button class="ui-btn primary" :disabled="!pickedFile || busy" @click="uploadAndDetect">
          {{ busy ? '检测中...' : '上传并检测' }}
        </button>
        <button class="ui-btn" :disabled="busy" @click="resetAll">清空</button>
      </div>

      <div v-if="errorMsg" class="ui-error">{{ errorMsg }}</div>
      <div v-if="successMsg" class="ui-success">{{ successMsg }}</div>

      <div v-if="detectResult" style="margin-top: 10px;">
        <h3 class="ui-subtitle">检测结果</h3>

        <div class="ui-hint" v-if="detectResult.ok">
          解析事件数：<b>{{ detectResult.event_count ?? '-' }}</b>；
          命中告警数：<b>{{ (detectResult.alerts || []).length }}</b>
        </div>

        <table class="ui-table" v-if="detectResult.alerts && detectResult.alerts.length">
          <thead>
            <tr>
              <th>规则标题</th>
              <th>Rule ID</th>
              <th>Level</th>
              <th>命中数量</th>
              <th>Tags</th>
              <th>证据摘要</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="a in detectResult.alerts" :key="a.rule_id + '_' + (a.title || '')">
              <td><b>{{ a.title || '-' }}</b></td>
              <td>{{ a.rule_id || '-' }}</td>
              <td>{{ a.level || '-' }}</td>
              <td>{{ a.hit_count ?? '-' }}</td>
              <td>{{ (a.tags || []).join(', ') || '-' }}</td>
              <td>
                <div v-if="a.evidence && a.evidence.length">
                  <div v-for="(e, idx) in a.evidence.slice(0, 5)" :key="idx">
                    <span style="color:#6b7280;">{{ e.field }}:</span> {{ e.value }}
                  </div>
                  <div class="ui-hint" v-if="a.evidence.length > 5">
                    仅展示前 5 条证据，共 {{ a.evidence.length }} 条
                  </div>
                </div>
                <div v-else>-</div>
              </td>
            </tr>
          </tbody>
        </table>

        <div v-else class="ui-hint">未命中任何 Sigma 规则。</div>

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
 * ======================= 后端需要实现的 API（EVTX + Sigma 检测） =======================
 *
 * Base: http://localhost:3000
 *
 * 1) 上传 EVTX 并进行 Sigma 检测
 *    - Method: POST
 *    - Path:   /detectEvtxWithSigma
 *    - Content-Type: multipart/form-data
 *    - FormData:
 *        file:         (binary) Windows EVTX 日志文件（必须 .evtx）
 *        label:        (string) 可选，日志标签
 *        rule_set:     (string) 可选，"enabled" | "all"
 *        return_level: (string) 可选，"summary" | "with_events"
 *
 *    - 语义:
 *        后端接收 EVTX 文件，解析为事件记录（建议转成统一字段结构），然后用 Sigma 规则进行检测匹配。
 *        注意：
 *          - 后端必须二次校验扩展名/内容（不要只信前端）
 *          - 限制文件大小与解析/检测超时
 *          - Sigma 检测建议缓存/预加载规则（避免每次都读库+解析）
 *
 *    - Response(建议 JSON):
 *        {
 *          ok: true,
 *          log_id: 8001,                 // 可选
 *          filename: "Security.evtx",
 *          sha256: "...",
 *          rule_set: "enabled",
 *          event_count: 12345,           // 解析出的事件数
 *          alerts: [
 *            {
 *              rule_id: "xxxx-xxxx-....",    // Sigma rule id（若有）
 *              title: "Suspicious ...",
 *              level: "high" | "medium" | "low" | "informational",
 *              tags: ["attack.txxxx", "..."],
 *              hit_count: 7,
 *              evidence: [                   // 摘要证据（建议只给少量字段）
 *                { field: "Image", value: "C:\\Windows\\..." },
 *                { field: "CommandLine", value: "..." }
 *              ],
 *              hit_event_ids: [12, 89, 102]  // 可选：命中事件索引/内部ID
 *            }
 *          ],
 *          // 当 return_level="with_events" 时，才返回详细命中事件（可能很大）
 *          hit_events: [
 *            { event_id: 12, time: "...", channel: "...", computer: "...", data: { ... } }
 *          ]
 *        }
 *
 * 失败返回：
 *   { ok:false, code:"NOT_EVTX"|"FILE_TOO_LARGE"|"PARSE_ERROR"|"DETECT_TIMEOUT"|"BAD_REQUEST"|"INTERNAL_ERROR", message:"..." }
 *
 * ============================================================================================
 */

import { ref } from "vue";
import axios from "axios";

const API_BASE = "http://localhost:3000";

const pickedFile = ref(null);
const logLabel = ref("");
const ruleSet = ref("enabled");
const returnLevel = ref("summary");

const busy = ref(false);
const errorMsg = ref("");
const successMsg = ref("");

const detectResult = ref(null);
const rawResp = ref("");

const MAX_FILE_SIZE_BYTES = 80 * 1024 * 1024; // 80MB

function resetMessages() {
  errorMsg.value = "";
  successMsg.value = "";
  rawResp.value = "";
  detectResult.value = null;
}

function resetAll() {
  pickedFile.value = null;
  logLabel.value = "";
  ruleSet.value = "enabled";
  returnLevel.value = "summary";
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

function isEvtx(name) {
  return lowerName(name).endsWith(".evtx");
}

async function uploadAndDetect() {
  resetMessages();

  if (!pickedFile.value) {
    errorMsg.value = "请先选择 EVTX 文件。";
    return;
  }

  const f = pickedFile.value;

  if (!isEvtx(f.name)) {
    errorMsg.value = "文件类型不正确：仅支持 .evtx。";
    return;
  }

  if (f.size > MAX_FILE_SIZE_BYTES) {
    errorMsg.value = `文件过大：${prettySize(f.size)}，请小于 ${prettySize(MAX_FILE_SIZE_BYTES)}。`;
    return;
  }

  try {
    busy.value = true;

    const fd = new FormData();
    fd.append("file", f);
    fd.append("label", logLabel.value || "");
    fd.append("rule_set", ruleSet.value || "enabled");
    fd.append("return_level", returnLevel.value || "summary");

    const resp = await axios.post(`${API_BASE}/detectEvtxWithSigma`, fd, {
      headers: { "Content-Type": "multipart/form-data" },
    });

    detectResult.value = resp.data;
    rawResp.value = JSON.stringify(resp.data, null, 2);
    successMsg.value = "检测完成了喵~";
  } catch (err) {
    console.error(err);
    errorMsg.value = "检测失败：请检查后端是否启动、API 是否实现，或稍后重试。";
  } finally {
    busy.value = false;
  }
}
</script>
