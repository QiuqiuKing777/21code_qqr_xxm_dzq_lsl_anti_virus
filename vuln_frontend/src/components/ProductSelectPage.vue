<template>
  <div>
    <h2>全局产品信息管理</h2>

    <!-- 查询部分 -->
    <h3>查询产品信息</h3>
    <input
      v-model="productId"
      type="text"
      placeholder="请输入产品 ID"
    />
    <button @click="searchProduct">查询</button>
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
          <tr v-for="item in result" :key="item.product_id">
            <td v-for="column in columns" :key="column">
              {{ item[column] || '无数据' }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else-if="result && result.length === 0">
      未找到相关产品信息。
    </div>

    <!-- 插入部分 -->
    <h3>插入产品信息</h3>
    <div v-for="column in columns" :key="column">
      <label :for="column">{{ formatColumnTitle(column) }}</label>
      <input
        v-model="newProduct[column]"
        type="text"
        :placeholder="column === 'product_id' ? '产品 ID' : column === 'product_name' ? '产品名称' : '产品版本'"
      />
    </div>
    <button @click="insertProduct">插入</button>
    <div v-if="insertError">{{ insertError }}</div>
    <div v-if="insertSuccess">插入成功！</div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import axios from 'axios';

// 数据表的列属性列表
const columns = ['product_id', 'product_name', 'product_version'];

// 格式化列标题
const formatColumnTitle = (column) => {
  const titleMap = {
    'product_id': '产品 ID',
    'product_name': '产品名称',
    'product_version': '产品版本'
  };
  return titleMap[column] || column;
};

// 存储用户输入的 product_id
const productId = ref('');
// 存储查询结果
const result = ref([]);
// 加载状态
const loading = ref(false);
// 错误信息
const error = ref('');

// 插入相关数据
const newProduct = ref({
  product_id: '',
  product_name: '',
  product_version: ''
});
const insertError = ref('');
const insertSuccess = ref(false);

// 定义搜索函数
const searchProduct = async () => {
  if (!productId.value.trim()) {
    error.value = '请输入有效的产品 ID';
    result.value = [];
    return;
  }

  loading.value = true;
  error.value = '';

  try {
    const response = await axios.get(`http://localhost:3000/ProductById/${productId.value}`);
    result.value = response.data; // 假设后端返回单个对象，包装为数组
  } catch (err) {
    error.value = '查询失败，请检查输入的产品 ID 或稍后重试';
    console.error(err);
  } finally {
    loading.value = false;
  }
};

// 定义插入函数
const insertProduct = async () => {
  if (!newProduct.value.product_name.trim() || !newProduct.value.product_version.trim()) {
    insertError.value = '产品名称和产品版本不能为空';
    return;
  }

  insertError.value = '';
  insertSuccess.value = false;

  try {
    await axios.post('http://localhost:3000/insertProduct', newProduct.value);
    insertSuccess.value = true;
    // 清空输入
    newProduct.value = {
      product_id: '',
      product_name: '',
      product_version: ''
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