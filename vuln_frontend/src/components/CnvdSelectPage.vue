<template>
  <div class="ui-card">
    <h2>CNVD 漏洞信息查询</h2>
    <!-- 查询部分 -->
    <input class="ui-input"
      v-model="cnvdId"
      type="text"
      placeholder="请输入 CNVD ID"
    />
    <button class ="ui-btn" @click="searchCnvd">查询</button>
    <div v-if="loading">加载中...</div>
    <div v-if="error">{{ error }}</div>
    <div v-if="result && result.length > 0">
      <h3>查询结果</h3>
      <table class="ui-table">
        <thead>
          <tr>
            <th v-for="column in columns" :key="column">{{ formatColumnTitle(column) }}</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="item in result" :key="item.cnvd_id">
            <td v-for="column in columns" :key="column">
              {{ item[column] || '无数据' }}
            </td>
            <td>
              <button class="ui-btn" @click="deleteCnvd(item.cnvd_id)">删除</button>
              <button class="ui-btn" @click="showUpdateForm = item.cnvd_id">更新</button>
            </td>
          </tr>
        </tbody>
      </table>
      <!-- 更新表单 -->
      <div v-if="showUpdateForm">
        <h3>更新 CNVD 漏洞信息</h3>
        <div v-for="column in columns" :key="column">
          <label class="ui-label" :for="column">{{ formatColumnTitle(column) }}</label>
          <input class="ui-input"
            v-model="updatedCnvd[column]"
            :type="column.includes('time') ? 'date' : 'text'"
            :placeholder="column.includes('time') ? '1999-09-09' : ''"
          />
        </div>
        <button class="ui-btn" @click="updateCnvd(showUpdateForm)">提交更新</button>
        <button class="ui-btn" @click="showUpdateForm = false">取消</button>
        <div v-if="updateError">{{ updateError }}</div>
        <div v-if="updateSuccess">更新成功！</div>
      </div>
    </div>
    <div v-else-if="result && result.length === 0">
      未找到相关漏洞信息。
    </div>

    <!-- 插入部分 -->
    <h2>插入 CNVD 漏洞信息</h2>
    <div v-for="column in columns" :key="column">
      <label class="ui-label" :for="column">{{ formatColumnTitle(column) }}</label>
      <input class="ui-input"
        v-model="newCnvd[column]"
        :type="column.includes('time') ? 'date' : 'text'"
        :placeholder="column.includes('time') ? '1999-09-09' : ''"
      />
    </div>
    <button class="ui-btn" @click="insertCnvd">插入</button>
    <div v-if="insertError">{{ insertError }}</div>
    <div v-if="insertSuccess">插入成功！</div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import axios from 'axios';

// 数据表的列属性列表
const columns = [
  'cnvd_id',
  'cnvd_title',
  'cnvd_msg',
  'cnvd_creattime',
  'cnvd_updatetime',
  'cnvd_reference_link',
  'cnvd_publisher',
  'cnvd_base_sever',
  'cnvd_base_severity'
];

// 格式化列标题
const formatColumnTitle = (column) => {
  const titleMap = {
    'cnvd_id': 'CNVD ID',
    'cnvd_title': '漏洞标题',
    'cnvd_msg': '漏洞信息',
    'cnvd_creattime': '创建时间',
    'cnvd_updatetime': '更新时间',
    'cnvd_reference_link': '参考链接',
    'cnvd_publisher': '发布者',
    'cnvd_base_sever': '威胁严重度（旧）',
    'cnvd_base_severity': '威胁严重度'
  };
  return titleMap[column] || column;
};

// 存储用户输入的 cnvd_id
const cnvdId = ref('');
// 存储查询结果
const result = ref(null);
// 加载状态
const loading = ref(false);
// 错误信息
const error = ref('');

// 插入相关数据
const newCnvd = ref({
  cnvd_id: '',
  cnvd_title: '',
  cnvd_msg: '',
  cnvd_creattime: '1999-09-09',
  cnvd_updatetime: '1999-09-09',
  cnvd_reference_link: '',
  cnvd_publisher: '',
  cnvd_base_sever: '',
  cnvd_base_severity: ''
});
const insertError = ref('');
const insertSuccess = ref(false);

// 更新相关数据
const showUpdateForm = ref(false);
const updatedCnvd = ref({});
const updateError = ref('');
const updateSuccess = ref(false);

// 定义搜索函数
const searchCnvd = async () => {
  if (!cnvdId.value.trim()) {
    error.value = '请输入有效的 CNVD ID';
    result.value = null;
    return;
  }

  loading.value = true;
  error.value = '';

  try {
    const response = await axios.get(`http://localhost:3000/CnvdVulnById/${cnvdId.value}`);
    result.value = response.data;
  } catch (err) {
    error.value = '查询失败，请检查输入的 CNVD ID 或稍后重试';
    console.error(err);
  } finally {
    loading.value = false;
  }
};

// 定义删除函数
const deleteCnvd = async (id) => {
  try {
    await axios.get(`http://localhost:3000/delCnvdVulnById/${id}`);
    // 删除成功后重新查询
    if (cnvdId.value.trim()) {
      await searchCnvd();
    }
  } catch (err) {
    error.value = '删除失败，请稍后重试';
    console.error(err);
  }
};

// 定义插入函数
const insertCnvd = async () => {
  if (!newCnvd.value.cnvd_id.trim()) {
    insertError.value = 'CNVD ID 不能为空，请输入有效的 CNVD ID';
    return;
  }

  insertError.value = '';
  insertSuccess.value = false;

  // 处理输入数据
  const processedData = {};
  for (const [key, value] of Object.entries(newCnvd.value)) {
    if (value === '') {
      processedData[key] = null;
    } else if (key === 'cnvd_base_sever' || key === 'cnvd_base_severity') {
      // 尝试将值转换为整数
      const numValue = parseInt(value, 10);
      processedData[key] = isNaN(numValue) ? null : numValue;
    } else {
      processedData[key] = value;
    }
  }

  try {
    await axios.post('http://localhost:3000/insertCnvdVuln', processedData);
    insertSuccess.value = true;
    // 清空输入
    newCnvd.value = {
      cnvd_id: '',
      cnvd_title: '',
      cnvd_msg: '',
      cnvd_creattime: '1999-09-09',
      cnvd_updatetime: '1999-09-09',
      cnvd_reference_link: '',
      cnvd_publisher: '',
      cnvd_base_sever: '',
      cnvd_base_severity: ''
    };
  } catch (err) {
    insertError.value = '插入失败，请稍后重试';
    console.error(err);
  }
};

// 定义更新函数
const updateCnvd = async (id) => {
  updateError.value = '';
  updateSuccess.value = false;

  // 处理输入数据
  const processedData = {};
  for (const [key, value] of Object.entries(updatedCnvd.value)) {
    if (value !== '') {
      if (key === 'cnvd_base_sever' || key === 'cnvd_base_severity') {
        const numValue = parseInt(value, 10);
        processedData[key] = isNaN(numValue) ? null : numValue;
      } else {
        processedData[key] = value;
      }
    }
  }

  try {
    await axios.put(`http://localhost:3000/updateCnvdVuln/${id}`, processedData);
    updateSuccess.value = true;
    showUpdateForm.value = false;
    // 更新成功后重新查询
    if (cnvdId.value.trim()) {
      await searchCnvd();
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