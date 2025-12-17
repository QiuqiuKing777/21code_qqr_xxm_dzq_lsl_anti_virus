<template>
  <div>
    <h2>威胁情报信息管理</h2>

    <!-- 查询部分 -->
    <h3>查询威胁情报信息</h3>
    <input
      v-model="atkMsgId"
      type="text"
      placeholder="请输入威胁情报 ID"
    />
    <button @click="searchAtkMsg">查询</button>
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
          <tr v-for="item in result" :key="item.msg_id">
            <td v-for="column in columns" :key="column">
              {{ item[column] || '无数据' }}
            </td>
            <td>
              <button @click="deleteAtkMsg(item.msg_id)">删除</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else-if="result && result.length === 0">
      未找到相关威胁情报信息。
    </div>

    <!-- 插入部分 -->
    <h3>插入威胁情报信息</h3>
    <div v-for="column in columns" :key="column">
      <label :for="column">{{ formatColumnTitle(column) }}</label>
      <input
        v-model="newAtkMsg[column]"
        type="text"
        :placeholder="column === 'msg_id' ? '威胁情报 ID' : column === 'vuln_id' ? '漏洞 ID' : column === 'product_id' ? '产品 ID' : '公司 ID'"
      />
    </div>
    <button @click="insertAtkMsg">插入</button>
    <div v-if="insertError">{{ insertError }}</div>
    <div v-if="insertSuccess">插入成功！</div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import axios from 'axios';

// 数据表的列属性列表
const columns = ['msg_id', 'vuln_id', 'product_id', 'company_id'];

// 格式化列标题
const formatColumnTitle = (column) => {
  const titleMap = {
    'msg_id': '威胁情报 ID',
    'vuln_id': '漏洞 ID',
    'product_id': '产品 ID',
    'company_id': '公司 ID'
  };
  return titleMap[column] || column;
};

// 存储用户输入的 atk_msg_id
const atkMsgId = ref('');
// 存储查询结果
const result = ref([]);
// 加载状态
const loading = ref(false);
// 错误信息
const error = ref('');

// 插入相关数据
const newAtkMsg = ref({
  msg_id: '',
  vuln_id: '',
  product_id: '',
  company_id: ''
});
const insertError = ref('');
const insertSuccess = ref(false);

// 定义搜索函数
const searchAtkMsg = async () => {
  if (!atkMsgId.value.trim()) {
    error.value = '请输入有效的威胁情报 ID';
    result.value = [];
    return;
  }

  loading.value = true;
  error.value = '';

  try {
    const response = await axios.get(`http://localhost:3000/AtkMsgById/${atkMsgId.value}`);
    result.value = response.data; // 假设后端返回单个对象，包装为数组
  } catch (err) {
    error.value = '查询失败，请检查输入的威胁情报 ID 或稍后重试';
    console.error(err);
  } finally {
    loading.value = false;
  }
};

// 定义插入函数
const insertAtkMsg = async () => {
  if (!newAtkMsg.value.vuln_id.trim() || !newAtkMsg.value.product_id.trim() || !newAtkMsg.value.company_id.trim()) {
    insertError.value = '漏洞 ID、产品 ID 和公司 ID 均不能为空';
    return;
  }

  insertError.value = '';
  insertSuccess.value = false;

  try {
    await axios.post('http://localhost:3000/insertMsg', newAtkMsg.value);
    insertSuccess.value = true;
    // 清空输入
    newAtkMsg.value = {
      msg_id: '',
      vuln_id: '',
      product_id: '',
      company_id: ''
    };
  } catch (err) {
    insertError.value = '插入失败，请稍后重试';
    console.error(err);
  }
};

// 定义删除函数
const deleteAtkMsg = async (msg_id) => {
  try {
    await axios.get(`http://localhost:3000/delMsgById/${msg_id}`);
    // 删除成功后重新查询
    if (atkMsgId.value.trim()) {
      await searchAtkMsg();
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