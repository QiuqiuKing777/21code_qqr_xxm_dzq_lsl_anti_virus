<template>
  <div>
    <h2>CVE 漏洞信息查询</h2>
    <!-- 查询部分 -->
    <input
      v-model="cveId"
      type="text"
      placeholder="请输入 CVE ID"
    />
    <button @click="searchCve">查询</button>
    <div v-if="loading">加载中...</div>
    <div v-if="error">{{ error }}</div>
    <div v-if="result && result.length > 0">
      <h3>查询结果</h3>
      <table>
        <thead>
          <tr>
            <th v-for="column in columns" :key="column">{{ formatColumnTitle(column) }}</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="item in result" :key="item.cve_id">
            <td v-for="column in columns" :key="column">
              {{ item[column] || '无数据' }}
            </td>
            <td>
              <button @click="deleteCve(item.cve_id)">删除</button>
              <button @click="showUpdateForm = item.cve_id">更新</button>
            </td>
          </tr>
        </tbody>
      </table>
      <!-- 更新表单 -->
      <div v-if="showUpdateForm">
        <h3>更新 CVE 漏洞信息</h3>
        <div v-for="column in columns" :key="column">
          <label :for="column">{{ formatColumnTitle(column) }}</label>
          <input
            v-model="updatedCve[column]"
            :type="column.includes('time') ? 'date' : 'text'"
            :placeholder="column.includes('time') ? '1999-09-09' : ''"
          />
        </div>
        <button @click="updateCve(showUpdateForm)">提交更新</button>
        <button @click="showUpdateForm = false">取消</button>
        <div v-if="updateError">{{ updateError }}</div>
        <div v-if="updateSuccess">更新成功！</div>
      </div>
    </div>
    <div v-else-if="result && result.length === 0">
      未找到相关漏洞信息。
    </div>

    <!-- 插入部分 -->
    <h2>插入 CVE 漏洞信息</h2>
    <div v-for="column in columns" :key="column">
      <label :for="column">{{ formatColumnTitle(column) }}</label>
      <input
        v-model="newCve[column]"
        :type="column.includes('time') ? 'date' : 'text'"
        :placeholder="column.includes('time') ? '1999-09-09' : ''"
      />
    </div>
    <button @click="insertCve">插入</button>
    <div v-if="insertError">{{ insertError }}</div>
    <div v-if="insertSuccess">插入成功！</div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import axios from 'axios';

// 数据表的列属性列表
const columns = [
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
    'cve_id': 'CVE ID',
    'cve_title': '漏洞标题',
    'cve_msg': '漏洞信息',
    'cve_creattime': '创建时间',
    'cve_updatetime': '更新时间',
    'cve_reference_link': '参考链接',
    'cve_publisher': '发布者',
    'cve_base_sever': '威胁严重度（旧）',
    'cve_base_severity': '威胁严重度'
  };
  return titleMap[column] || column;
};

// 存储用户输入的 cve_id
const cveId = ref('');
// 存储查询结果
const result = ref(null);
// 加载状态
const loading = ref(false);
// 错误信息
const error = ref('');

// 插入相关数据
const newCve = ref({
  cve_id: '',
  cve_title: '',
  cve_msg: '',
  cve_creattime: '1999-09-09',
  cve_updatetime: '1999-09-09',
  cve_reference_link: '',
  cve_publisher: '',
  cve_base_sever: null,
  cve_base_severity: null
});
const insertError = ref('');
const insertSuccess = ref(false);

// 更新相关数据
const showUpdateForm = ref(false);
const updatedCve = ref({});
const updateError = ref('');
const updateSuccess = ref(false);

// 定义搜索函数
const searchCve = async () => {
  if (!cveId.value.trim()) {
    error.value = '请输入有效的 CVE ID';
    result.value = null;
    return;
  }

  loading.value = true;
  error.value = '';

  try {
    const response = await axios.get(`http://localhost:3000/CveVulnById/${cveId.value}`);
    result.value = response.data;
  } catch (err) {
    error.value = '查询失败，请检查输入的 CVE ID 或稍后重试';
    console.error(err);
  } finally {
    loading.value = false;
  }
};

// 定义删除函数
const deleteCve = async (id) => {
  try {
    await axios.get(`http://localhost:3000/delCveVulnById/${id}`);
    // 删除成功后重新查询
    if (cveId.value.trim()) {
      await searchCve();
    }
  } catch (err) {
    error.value = '删除失败，请稍后重试';
    console.error(err);
  }
};

// 定义插入函数
const insertCve = async () => {
  if (!newCve.value.cve_id.trim()) {
    insertError.value = 'CVE ID 不能为空，请输入有效的 CVE ID';
    return;
  }

  insertError.value = '';
  insertSuccess.value = false;

  // 处理输入数据
  const processedData = {};
  for (const [key, value] of Object.entries(newCve.value)) {
    if (value === '') {
      processedData[key] = null;
    } else if (key === 'cve_base_sever' || key === 'cve_base_severity') {
      // 尝试将值转换为整数
      const numValue = parseInt(value, 10);
      processedData[key] = isNaN(numValue) ? null : numValue;
    } else {
      processedData[key] = value;
    }
  }

  try {
    await axios.post('http://localhost:3000/insertCveVuln', processedData);
    insertSuccess.value = true;
    // 清空输入
    newCve.value = {
      cve_id: '',
      cve_title: '',
      cve_msg: '',
      cve_creattime: '1999-09-09',
      cve_updatetime: '1999-09-09',
      cve_reference_link: '',
      cve_publisher: '',
      cve_base_sever: null,
      cve_base_severity: null
    };
  } catch (err) {
    insertError.value = '插入失败，请稍后重试';
    console.error(err);
  }
};

// 定义更新函数
const updateCve = async (id) => {
  updateError.value = '';
  updateSuccess.value = false;

  // 处理输入数据
  const processedData = {};
  for (const [key, value] of Object.entries(updatedCve.value)) {
    if (value !== '') {
      if (key === 'cve_base_sever' || key === 'cve_base_severity') {
        const numValue = parseInt(value, 10);
        processedData[key] = isNaN(numValue) ? null : numValue;
      } else {
        processedData[key] = value;
      }
    }
  }

  try {
    await axios.put(`http://localhost:3000/updateCveVuln/${id}`, processedData);
    updateSuccess.value = true;
    showUpdateForm.value = false;
    // 更新成功后重新查询
    if (cveId.value.trim()) {
      await searchCve();
    }
  } catch (err) {
    updateError.value = '更新失败，请稍后重试';
    console.error(err);
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