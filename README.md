# ikuai-komari-agent

监控 **iKuai（爱快）路由器**，并将数据通过 **Komari v2 协议**上报到 Komari 面板。

单文件、零第三方依赖（仅 Python 标准库），镜像基于 `python:3.9-slim`。

## 为什么需要它

- 官方 [komari-agent](https://github.com/komari-monitor/komari-agent) 只能采集运行它的那台机器，无法运行在爱快上；
- 社区 [ikuai-komari-agent](https://github.com/ZeroTwoDa/ikuai-komari-agent) 使用 Komari 旧版上报接口（`/api/clients/uploadBasicInfo`），在 **Komari 1.6.x** 上 404；
- iKuai **4.0** 移除了 `sysstat` 的 `load` / `disk` TYPE，且强制 HTTPS + 自签名证书。

本项目针对以上三点做了适配：

| 特性 | 说明 |
|---|---|
| API Token 认证 | iKuai 4.0.222+ 个人 API 令牌（Bearer），免账号密码、不触发登录锁定 |
| 账密兼容模式 | iKuai 3.x 走 `/Action/login` 会话模式 |
| Komari v2 协议 | JSON-RPC over HTTP（`/api/clients/v2/rpc`），适配 Komari 1.6.x |
| iKuai 4.0 兼容 | 走 OpenAPI v4.0（`/api/v4.0/monitoring/*`），无旧接口兼容问题 |
| 自签名证书 | 默认跳过 iKuai HTTPS 证书校验（`IKUAI_VERIFY_SSL=false`） |
| 零依赖 | 无需 pip 安装任何包 |

## 采集内容

CPU 使用率 / 内存 / 磁盘用量 / 上下行速率与总流量 / TCP、UDP 连接数 / 运行时间 / 核心数 / 系统版本

## 获取爱快 API 令牌（推荐方式）

1. 登录爱快 4.0+ 管理后台
2. 进入 **登录管理 → 个人 API 令牌**（部分版本在设备设置/高级设置下）
3. 点击 **添加**，名称随意（如 `komari`），权限勾选：**负载监控、接口监控、终端监控**
4. 复制生成的令牌（只显示一次）

> 令牌仅具备勾选的只读权限，无需暴露管理员密码，也不会触发登录防爆破锁定。

iKuai 3.x 无此功能，可改用账号密码模式（见环境变量 `IKUAI_USERNAME` / `IKUAI_PASSWORD`）。

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `IKUAI_URL` | `https://192.168.1.1` | 爱快管理地址（支持 http/https） |
| `IKUAI_API_TOKEN` | 无 | 爱快 4.0.222+ 个人 API 令牌（**推荐**，设置后忽略账密） |
| `IKUAI_USERNAME` | 无 | 爱快账号（仅 3.x 账密模式） |
| `IKUAI_PASSWORD` | 无 | 爱快密码（仅 3.x 账密模式） |
| `IKUAI_VERIFY_SSL` | `false` | 自签名证书设为 false |
| `IKUAI_TIMEOUT` | `10` | 请求超时（秒） |
| `KOMARI_ENDPOINT` | 无（必填） | Komari 面板地址 |
| `KOMARI_TOKEN` | 无（必填） | 节点 Token（面板后台节点管理中获取，**不是**自动发现令牌） |
| `REPORT_INTERVAL` | `3` | 指标上报间隔（秒） |
| `BASIC_INTERVAL` | `300` | 基础信息上报间隔（秒） |
| `LOCK_BACKOFF` | `60` | 账密模式下登录被锁定时的退避秒数 |
| `MONTH_ROTATE` | `0` | 流量月重置日（0=不重置；1-28=每月 N 号清零，同官方 `--month-rotate`） |
| `STATE_FILE` | `/data/traffic_state.json` | 月流量基线持久化文件（建议挂载卷，重启不丢当月统计） |

## Docker 运行

镜像由 GitHub Actions 自动构建发布（amd64 / arm64）：

- GHCR：`ghcr.io/po9873/ikuai-komari-agent:latest`
- Docker Hub：`po9873/ikuai-komari-agent:latest`

```bash
docker run -d \
  --name ikuai-komari-agent \
  --restart=unless-stopped \
  --network host \
  -e IKUAI_URL=https://192.168.1.1 \
  -e IKUAI_API_TOKEN=你的爱快令牌 \
  -e KOMARI_ENDPOINT=http://komari-server:25774 \
  -e KOMARI_TOKEN=你的节点Token \
  ghcr.io/po9873/ikuai-komari-agent:latest
```

或使用 docker-compose：

```bash
cp .env.example .env  # 编辑配置
docker compose up -d
```

## 自动构建（GitHub Actions）

推送到 `main` 或打 `v*` 标签即自动构建并推送镜像到 GHCR 与 Docker Hub。Docker Hub 推送需在仓库 **Settings → Secrets and variables → Actions** 配置 `DOCKERHUB_USERNAME` 和 `DOCKERHUB_TOKEN`（Docker Hub → Account Settings → Security → Access Token 生成）。

## 本地调试

```bash
export IKUAI_URL=https://192.168.1.1
export IKUAI_API_TOKEN=你的爱快令牌
export KOMARI_ENDPOINT=http://komari-server:25774
export KOMARI_TOKEN=你的节点Token
python agent.py
```

## License

MIT
