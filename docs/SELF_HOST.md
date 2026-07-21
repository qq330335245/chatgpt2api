# 独立部署指南（自己的 GitHub + GHCR + 服务器 Docker）

本仓库已从上游逻辑解耦，可直接推送到你自己的 GitHub 仓库，用 Actions 自动构建镜像并部署到服务器。

## 1. 创建你自己的 GitHub 仓库

1. 在 GitHub 新建空仓库（建议私有），例如 `chatgpt2api`。
2. 不要勾选自动添加 README（本地已有完整代码）。
3. 记下仓库地址：
   - HTTPS: `https://github.com/<your-username>/chatgpt2api.git`
   - SSH: `git@github.com:<your-username>/chatgpt2api.git`

## 2. 绑定远程并推送

本机当前约定：

- `upstream` -> 原项目 `basketikun/chatgpt2api`（只读同步参考）
- `origin` -> **你自己的仓库**

```bash
# 如果还没有设置 origin：
git remote add origin https://github.com/<your-username>/chatgpt2api.git

# 推送主分支与构建工作流
git push -u origin main

# 可选：推送标签触发正式版本构建
git tag v1.6.1
git push origin v1.6.1
```

## 3. 开启自动构建（GHCR）

仓库已包含 `.github/workflows/docker-publish.yml`：

- 推送到 `main`：构建并推送 `latest` 等标签
- 推送 `v*` 标签：构建语义化版本镜像
- 也可在 Actions 页手动 `workflow_dispatch`

镜像地址格式：

```text
ghcr.io/<your-username>/chatgpt2api:latest
ghcr.io/<your-username>/chatgpt2api:v1.6.1
```

首次拉取私有包时，服务器需要登录 GHCR：

```bash
echo <GITHUB_TOKEN> | docker login ghcr.io -u <your-username> --password-stdin
```

Token 权限至少包含 `read:packages`；若要在网页上可见/管理 package，可能还需要在 GitHub Package 设置里授权仓库读写。

## 4. 服务器 Docker 部署

```bash
# 服务器上准备目录
mkdir -p /opt/chatgpt2api && cd /opt/chatgpt2api

# 放一份 config.json（务必修改 auth-key）
# 可用仓库示例 config 作为起点，不要提交真实密钥

# .env
cat > .env <<'EOF'
CHATGPT2API_IMAGE=ghcr.io/<your-username>/chatgpt2api:latest
CHATGPT2API_AUTH_KEY=change-me
EOF

# docker-compose.yml 可从本仓库复制
# 默认会读 CHATGPT2API_IMAGE；未设置时本地 build

docker compose pull
docker compose up -d
```

访问：

- Web: `http://<server-ip>:3000`
- API: `http://<server-ip>:3000/v1`

## 5. 更新流程

```bash
# 本地改完推 main
git push origin main

# 服务器拉新镜像并重启
docker compose pull
docker compose up -d
```

## 6. 与上游同步（可选）

```bash
git fetch upstream
git merge upstream/main
# 解决冲突后
git push origin main
```

注意：上游 `main` 可能已移除注册相关能力；本独立分支保留并增强了注册/重新登录能力，合并时请仔细处理冲突。
