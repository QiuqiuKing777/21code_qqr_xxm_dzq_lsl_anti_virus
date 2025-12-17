# 部署文档 🐱

> 本文档用于指导系统的完整部署流程，包括 **前端、后端与数据库** 的配置说明。
> 
> 感谢作者@wagga40等在https://github.com/wagga40/Zircolite# 提供的Zircolite sigma规则扫描引擎

---
## 〇、死活配不出来？
问秋秋人，不要怕麻烦秋秋人。o(=•ェ•=)m
## 一、部署环境说明

### 1. 虚拟机部署（推荐）

- 建议使用 **Windows 10**
- 在开始配置前，请 **关闭 Windows 实时防护**
- 适合测试 **YARA 规则扫描功能**

### 2. 本机部署（不推荐测试 YARA）

- 不建议在本机上测试 **YARA 规则扫描**（~~千万不要~~）
- 尚未完全验证其是否能良好隔离恶意文件

---

## 二、数据库配置（MySQL）

### 1. 数据库要求

- 数据库类型：**MySQL**
- 版本要求：**至少兼容 MySQL 5.7**
- 如果在虚拟机中部署，通常需要重新安装 MySQL  
安装时请注意 **版本兼容性**

包里提供了适合的版本的mysql，但是他依赖于VC_resist，如果您的电脑之前没有安装这个，
运行随在包里的exe程序进行安装。

数据库安装时的配置如下：
- 组件选择：MySQL server +MySQL client
- config type：Development Computer
- authentication method:Use Legacy Authentication Method (mysql_native_password)
- Windows Service:选择Configure MySQL Server as a Windows Service + Start the MySQL Server at System Startup


### 2. 初始化数据库

1. 安装完成后，请记住 **root 用户的密码**
2. 创建数据库：

```sql
CREATE DATABASE nvd_database;
```

> 数据库名可以修改，但请确保后端连接串同步修改

3. 运行 `nvd_database.sql`，自动创建以下表：
   - `sigma_rule`
   - `yara_rule`
   - 如何运行？-mysql界面，左上角file->open sql script->闪电图标
4. （可选）运行 `yara_rule.sql` 以导入示例规则

---

## 三、目录放置建议

- 虚拟机部署建议放在 **桌面**
- 本机部署可放在任意目录

---

## 四、后端配置（vuln_backend）

1. 拷贝 `vuln_backend` 到任意目录
2. 编辑 `./src/config.py`，根据数据库配置修改连接串

---

## 五、Python 环境配置

1. 解压 `python39_64` 到任意目录
2. 将其加入系统 Path（置于最前）（路径截取到.../python39_64）
3. 验证：

```bash
python -version
```
要能出现正确的版本号3.9.13，而不只是出现版本号。

---

## 六、启动后端服务

```bash
cd vuln_backend
python -m src.run
```

如缺少依赖，使用：

```bash
python -m pip install 包名
```

常见依赖包括：

- markupsafe
- PyYAML
- pymysql
- flask-cors
- Jinja2
- importlib-metadata
- python-dateutil
- typing-extensions

循环执行以下步骤直到成功：

+ 运行后端

+ 查看报错

+ 安装缺失依赖

当看到 后端日志信息正常输出 时，说明启动成功

---

## 七、前端配置

在 `dist` 目录下运行：

```bash
python -m http.server 8081
```

访问：

```text
http://127.0.0.1:8081/index.html
```

---

## 八、部署成功测试（YARA）

1. 上传 `lab01-01.dll`
2. 若显示规则命中及后端信息，则部署成功🐱
