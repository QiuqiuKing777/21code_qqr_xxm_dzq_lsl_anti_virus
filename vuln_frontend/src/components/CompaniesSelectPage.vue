<template>
  <div>
    <h2>公司信息管理</h2>

    <!-- 查询部分 -->
    <h3>查询公司信息</h3>
    <input
      v-model="companyId"
      type="text"
      placeholder="请输入公司 ID"
    />
    <button @click="searchCompany">查询</button>
    <div v-if="loading">加载中...</div>
    <div v-if="error">{{ error }}</div>
    <div v-if="result && result.length > 0">
      <h4>查询结果</h4>
      <table>
        <thead>
          <tr>
            <th v-for="column in columns" :key="column">{{ formatColumnTitle(column) }}</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="item in result" :key="item.company_id">
            <td v-for="column in columns" :key="column">
              {{ item[column] || '无数据' }}
            </td>
            <td>
              <button @click="deleteCompany(item.company_id)">删除</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else-if="result && result.length === 0">
      未找到相关公司信息。
    </div>

    <!-- 插入部分 -->
    <h3>插入公司信息</h3>
    <div v-for="column in columns" :key="column">
      <label :for="column">{{ formatColumnTitle(column) }}</label>
      <input
        v-model="newCompany[column]"
        type="text"
        :placeholder="column === 'company_id' ? '自动生成' : ''"
        :disabled="column === 'company_id'"
      />
    </div>
    <button @click="insertCompany">插入</button>
    <div v-if="insertError">{{ insertError }}</div>
    <div v-if="insertSuccess">插入成功！</div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import axios from 'axios';

// 数据表的列属性列表
const columns = ['company_id', 'company_name', 'finance_scale'];

// 格式化列标题
const formatColumnTitle = (column) => {
  const titleMap = {
    'company_id': '公司 ID',
    'company_name': '公司名称',
    'finance_scale': '融资规模'
  };
  return titleMap[column] || column;
};

// 存储用户输入的 company_id
const companyId = ref('');
// 存储查询结果
const result = ref([]);
// 加载状态
const loading = ref(false);
// 错误信息
const error = ref('');

// 插入相关数据
const newCompany = ref({
  company_id: null,
  company_name: '',
  finance_scale: ''
});
const insertError = ref('');
const insertSuccess = ref(false);

// 定义搜索函数
const searchCompany = async () => {
  if (!companyId.value.trim()) {
    error.value = '请输入有效的公司 ID';
    result.value = [];
    return;
  }

  loading.value = true;
  error.value = '';

  try {
    const response = await axios.get(`http://localhost:3000/CompanyById/${companyId.value}`);
    result.value = response.data; // 假设后端返回单个对象，包装为数组
  } catch (err) {
    error.value = '查询失败，请检查输入的公司 ID 或稍后重试';
    console.error(err);
  } finally {
    loading.value = false;
  }
};

// 定义插入函数
const insertCompany = async () => {
  if (!newCompany.value.company_name.trim() || !newCompany.value.finance_scale.trim()) {
    insertError.value = '公司名称和融资规模不能为空';
    return;
  }

  insertError.value = '';
  insertSuccess.value = false;

  try {
    await axios.post('http://localhost:3000/insertCompany', newCompany.value);
    insertSuccess.value = true;
    // 清空输入
    newCompany.value = {
      company_id: '',
      company_name: '',
      finance_scale: ''
    };
  } catch (err) {
    insertError.value = '插入失败，请稍后重试';
    console.error(err);
  }
};

// 定义删除函数
const deleteCompany = async (id) => {
  try {
    await axios.get(`http://localhost:3000/delCompany/${id}`);
    // 删除成功后重新查询
    if (companyId.value.trim()) {
      await searchCompany();
    }
  } catch (err) {
    error.value = '删除失败，请稍后重试';
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