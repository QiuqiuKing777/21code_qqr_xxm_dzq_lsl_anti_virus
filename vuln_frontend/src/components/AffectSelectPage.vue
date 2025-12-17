<template>
  <div>
    <h2>漏洞影响信息管理</h2>

    <!-- 查询部分 -->
    <h3>查询漏洞影响信息</h3>
    <div>
      <label for="vulnId">漏洞 ID：</label>
      <input
        v-model="vulnId"
        type="text"
        placeholder="请输入漏洞 ID"
      />
    </div>
    <div>
      <label for="productId">产品 ID：</label>
      <input
        v-model="productId"
        type="text"
        placeholder="请输入产品 ID"
      />
    </div>
    <button @click="searchAffect">查询</button>
    <div v-if="loading">加载中...</div>
    <div v-if="error">{{ error }}</div>
    <div v-if="result && result.length > 0">
      <h4>查询结果</h4>
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
      未找到相关漏洞影响信息。
    </div>

    <!-- 插入部分 -->
    <h3>插入漏洞影响信息</h3>
    <div v-for="column in columns" :key="column">
      <label :for="column">{{ formatColumnTitle(column) }}</label>
      <input
        v-model="newAffect[column]"
        type="text"
        :placeholder="column === 'vuln_id' ? '漏洞 ID' : '产品 ID'"
      />
    </div>
    <button @click="insertAffect">插入</button>
    <div v-if="insertError">{{ insertError }}</div>
    <div v-if="insertSuccess">插入成功！</div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import axios from 'axios';

// 数据表的列属性列表
const columns = ['vuln_id', 'product_id'];

// 格式化列标题
const formatColumnTitle = (column) => {
  const titleMap = {
    'vuln_id': '漏洞 ID',
    'product_id': '产品 ID'
  };
  return titleMap[column] || column;
};

// 存储用户输入的 vuln_id 和 product_id
const vulnId = ref('');
const productId = ref('');
// 存储查询结果
const result = ref([]);
// 加载状态
const loading = ref(false);
// 错误信息
const error = ref('');

// 插入相关数据
const newAffect = ref({
  vuln_id: '',
  product_id: ''
});
const insertError = ref('');
const insertSuccess = ref(false);

// 定义搜索函数
const searchAffect = async () => {
  if (!vulnId.value.trim() || !productId.value.trim()) {
    error.value = '漏洞 ID 和产品 ID 均不能为空';
    result.value = [];
    return;
  }

  loading.value = true;
  error.value = '';

  try {
    const response = await axios.get(`http://localhost:3000/Affects/${vulnId.value}/${productId.value}`);
    result.value = response.data; // 假设后端返回的是数组
  } catch (err) {
    error.value = '查询失败，请检查输入的漏洞 ID 和产品 ID 或稍后重试';
    console.error(err);
  } finally {
    loading.value = false;
  }
};

// 定义插入函数
const insertAffect = async () => {
  if (!newAffect.value.vuln_id.trim() || !newAffect.value.product_id.trim()) {
    insertError.value = '漏洞 ID 和产品 ID 均不能为空';
    return;
  }

  insertError.value = '';
  insertSuccess.value = false;

  try {
    await axios.post('http://localhost:3000/insertAffect', newAffect.value);
    insertSuccess.value = true;
    // 清空输入
    newAffect.value = {
      vuln_id: '',
      product_id: ''
    };
  } catch (err) {
    insertError.value = '插入失败，请稍后重试';
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