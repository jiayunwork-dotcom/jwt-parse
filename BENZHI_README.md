# jwt-parse — Go 语言 JWT 令牌解析、签名与验证 HTTP 后端服务，支持多密钥环 (kid)、密钥轮换、策略引擎和吊销列表

## 构建 / 运行 / 测试

```text
go build ./...                          # 编译
go run . -addr :8080                    # 启动 HTTP 服务（/api/inspect, /api/verify, /api/sign）
go test ./...                           # 测试
```

## 评测镜像

本目录评测专用文件（勿覆盖项目自带 Dockerfile/README）：

- `benzhi.Dockerfile`
- `build_benzhi_docker.sh`
- `BENZHI_README.md`（本文件）

两种架构都要构建并进容器验证：

```bash
chmod +x build_benzhi_docker.sh
./build_benzhi_docker.sh <image-name> linux/arm64
./build_benzhi_docker.sh <image-name> linux/amd64
docker run -it <image-name>:latest
```
