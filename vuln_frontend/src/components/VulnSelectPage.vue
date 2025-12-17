<template>
  <div>
    <h2>Vuln 漏洞信息查询</h2>
    <!-- 查询部分 -->
    <input
      v-model="vulnId"
      type="text"
      placeholder="请输入 Vuln ID"
    />
    <button @click="searchVuln">查询</button>
    <div v-if="loading">加载中...</div>
    <div v-if="error">{{ error }}</div>
    <div v-if="result && result.length > 0">
      <h3>查询结果</h3>
      <table>
        <thead>
          <tr>
            <th v-for="column in columns" :key="column">{{ formatColumnTitle(column) }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="item in result" :key="item.vuln_id">
            <td v-for="column in columns" :key="column">
              {{ item[column] || '无数据' }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else-if="result && result.length === 0">
      未找到相关漏洞信息。
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import axios from 'axios';

// 数据表的列属性列表
const columns = [
  'vuln_id',
  'vuln_cve_id',
  'vuln_cnvd_id',
  'cnvd_id',
  'cnvd_title',
  'cnvd_msg',
  'cnvd_creattime',
  'cnvd_updatetime',
  'cnvd_reference_link',
  'cnvd_publisher',
  'cnvd_base_sever',
  'cnvd_base_severity',
  'cve_id',
  'cve_title',
  'cve_msg',
  'cve_creattime',
  'cve_updatetime',
  'cve_reference_link',
  'cve_publisher',
  'cve_base_sever',
  'cve_base_severity'
];

// 格式化列标题
const formatColumnTitle = (column) => {
  const titleMap = {
    'vuln_id': 'Vuln ID',
    'vuln_cve_id': 'CVE ID',
    'vuln_cnvd_id': 'CNVD ID',
    'cnvd_id': 'CNVD ID',
    'cnvd_title': 'CNVD 标题',
    'cnvd_msg': 'CNVD 消息',
    'cnvd_creattime': 'CNVD 创建时间',
    'cnvd_updatetime': 'CNVD 更新时间',
    'cnvd_reference_link': 'CNVD 参考链接',
    'cnvd_publisher': 'CNVD 发布者',
    'cnvd_base_sever': 'CNVD 基础严重性',
    'cnvd_base_severity': 'CNVD 基础严重性等级',
    'cve_id': 'CVE ID',
    'cve_title': 'CVE 标题',
    'cve_msg': 'CVE 消息',
    'cve_creattime': 'CVE 创建时间',
    'cve_updatetime': 'CVE 更新时间',
    'cve_reference_link': 'CVE 参考链接',
    'cve_publisher': 'CVE 发布者',
    'cve_base_sever': 'CVE 基础严重性',
    'cve_base_severity': 'CVE 基础严重性等级'
  };
  return titleMap[column] || column;
};

// 存储用户输入的 vuln_id
const vulnId = ref('');
// 存储查询结果
const result = ref(null);
// 加载状态
const loading = ref(false);
// 错误信息
const error = ref('');

// 定义搜索函数
const searchVuln = async () => {
  if (!vulnId.value.trim()) {
    error.value = '请输入有效的 Vuln ID';
    result.value = null;
    return;
  }

  loading.value = true;
  error.value = '';

  try {
    const response = await axios.get(`http://localhost:3000/VulnById/${vulnId.value}`);
    result.value = response.data; // 假设后端返回单个对象，包装为数组
  } catch (err) {
    error.value = '查询失败，请检查输入的 Vuln ID 或稍后重试';
    console.error(err);
  } finally {
    loading.value = false;
  }
};
</script>

<style scoped>
table {
  border-collapse: collapse;
  width: 100%;
}

th, td {
  border: 1px solid #ddd;
  padding: 8px;
  text-align: left;
}

th {
  background-color: #f2f2f2;
}
</style>