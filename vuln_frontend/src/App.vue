<template>
  <div id="app">
    <!-- 顶栏 -->
    <header class="top-bar">
      <div class="brand">
        <div class="brand-dot"></div>
        <div class="brand-text">
          <div class="brand-title">Anti-virus</div>
          <div class="brand-sub">殺殺毒喵喵喵o(=•ェ•=)m~</div>
        </div>
      </div>
    </header>

    <!-- 左侧栏 -->
    <aside class="sidebar">
      <h3>Navigation</h3>
      <input type="text" v-model="searchQuery" placeholder="搜索功能" @input="filterOptions" />
      <ul>
        <li
          v-for="option in filteredOptions"
          :key="option.value"
          @click="redirectTo(option.route)"
        >
          {{ option.label }}
        </li>
      </ul>
    </aside>

    <!-- 主内容区 -->
    <main class="main-content">
      <div class="content-shell">
        <router-view></router-view>
      </div>
    </main>
  </div>
</template>

<script>
export default {
  name: "App",
  data() {
    return {
      searchQuery: "",
      options: [
        // { label: "Vuln 系统漏洞数据管理", route: "/vuln_database" },
        // { label: "CNVD 漏洞数据管理", route: "/cnvd_database" },
        // { label: "CVE 漏洞数据管理", route: "/cve_database" },
        // { label: "公司管理", route: "/company_database" },
        // { label: "全局产品管理", route: "/product_database" },
        // { label: "威胁情报管理", route: "/atkmsg_database" },
        // { label: "产品使用情况管理", route: "/used_database" },
        // { label: "漏洞影响管理", route: "/affects_database" },
        { label: "yara规则上传",route: "/yara_upload"},
        { label: "sigma规则上传",route: "/sigma_upload"},
        { label: "yara规则检测",route: "/yara_scan"},
        { label: "sigma规则检测",route: "/sigma_scan"}
      ],
      filteredOptions: [],
    };
  },
  methods: {
    filterOptions() {
      if (!this.searchQuery) {
        this.filteredOptions = this.options;
      } else {
        this.filteredOptions = this.options.filter((option) =>
          option.label.toLowerCase().includes(this.searchQuery.toLowerCase())
        );
      }
    },
    redirectTo(route) {
      this.$router.push(route);
    },
  },
  mounted() {
    this.filteredOptions = this.options;
  },
};
</script>

<style scoped>
:global(html, body) {
  height: 100%;
  margin: 0;
}
:global(body) {
  background: radial-gradient(circle at 20% 10%, rgba(180, 190, 255, 0.45), transparent 40%),
    radial-gradient(circle at 80% 30%, rgba(210, 160, 255, 0.35), transparent 45%),
    radial-gradient(circle at 40% 80%, rgba(160, 210, 255, 0.35), transparent 50%),
    #f6f7fb;
}

#app {
  height: 100vh;
  font-family: Arial, sans-serif;
}

/* 顶栏 */
.top-bar {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  height: 84px;
  display: flex;
  align-items: center;
  padding: 0 24px;
  background: rgba(255, 255, 255, 0.55);
  backdrop-filter: blur(10px);
  border-bottom: 1px solid rgba(255, 255, 255, 0.6);
  z-index: 10;
}

/* “Vuln Panel / 管理面板” 拉长成一个品牌条 */
.brand {
  display: flex;
  align-items: center;
  gap: 12px;
  height: 56px;
  min-width: 320px;          /* 你要“拉长”的关键：最小宽度 */
  padding: 0 18px;
  border-radius: 16px;
  background: rgba(255, 255, 255, 0.78);
  box-shadow: 0 10px 30px rgba(20, 30, 60, 0.10);
}

.brand-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: #7c3aed;       /* 紫色点 */
  flex: 0 0 auto;
}
.brand-text {
  display: flex;
  flex-direction: column;
  line-height: 1.1;
}
.brand-title {
  font-size: 18px;
  font-weight: 700;
  color: #111827;
}
.brand-sub {
  font-size: 12px;
  color: #6b7280;
  margin-top: 2px;
}

/* 左侧栏 */
.sidebar {
  position: fixed;
  top: 84px;                 /* 跟顶栏高度一致 */
  left: 0;
  bottom: 0;
  width: 240px;              /* 略加宽一点，视觉更像仪表盘 */
  padding: 18px 16px;
  background: rgba(255, 255, 255, 0.55);
  backdrop-filter: blur(10px);
  border-right: 1px solid rgba(255, 255, 255, 0.6);
  z-index: 5;
  overflow: auto;
  border-top-right-radius: 18px;
}

.sidebar h3 {
  margin: 10px 10px 10px;
  font-size: 18px;
  font-weight: 800;
  letter-spacing: 0.3px;
  color: #111827;
  padding: 6px 10px;
  border-radius: 12px;
  background: rgba(124, 58, 237, 0.10);
}

.sidebar input {
  width: calc(100% - 16px);
  margin: 0 8px 12px;
  padding: 10px 12px;
  border: 1px solid rgba(15, 23, 42, 0.08);
  border-radius: 12px;
  background: rgba(255, 255, 255, 0.9);
  color: #111827;
  outline: none;
}

.sidebar ul {
  list-style: none;
  padding: 0 6px;
  margin: 0;
}

.sidebar li {
  cursor: pointer;
  padding: 12px 12px;
  margin: 6px 2px;
  border-radius: 14px;
  color: #111827;
  background: rgba(255, 255, 255, 0.65);
  border: 1px solid rgba(15, 23, 42, 0.06);
  transition: transform 0.08s ease, background 0.12s ease;
}

.sidebar li:hover {
  background: rgba(124, 58, 237, 0.10);
  transform: translateY(-1px);
}

/* 主内容区：真正占满剩余空间 */
.main-content {
  position: fixed;
  top: 84px;
  left: 240px;               /* = sidebar width */
  right: 0;
  bottom: 0;
  padding: 18px;
  overflow: auto;
}

/* 给 router-view 一个“撑满容器”的壳，避免子组件默认居中缩成一条 */
.content-shell {
  min-height: calc(100vh - 84px - 36px);
  width: 100%;
  border-radius: 18px;
  background: rgba(255, 255, 255, 0.55);
  backdrop-filter: blur(10px);
  border: 1px solid rgba(255, 255, 255, 0.65);
  box-shadow: 0 18px 60px rgba(20, 30, 60, 0.10);
  padding: 18px;
  box-sizing: border-box;
}
</style>
