# vkeyd 多用户测试用镜像（本地/CI 验证 admin 模式与配额）
# 构建上下文是仓库根：docker build -f server/deploy/Dockerfile .
FROM golang:1.27-alpine AS build
# 国内网络下走镜像代理；海外可覆盖为 direct
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}
WORKDIR /src
COPY server/go.mod server/go.sum ./server/
RUN cd server && go mod download
COPY server ./server
RUN cd server && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/vkeyd ./cmd/vkeyd

FROM alpine:3.20
RUN adduser -D -u 10001 vkey
COPY --from=build /out/vkeyd /usr/local/bin/vkeyd
RUN mkdir -p /data && chown vkey:vkey /data
USER vkey
WORKDIR /data
EXPOSE 3150
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/vkeyd"]
CMD ["serve", "--db", "/data/vkeyd.db", "--listen", "0.0.0.0:3150", "--domain", "localhost"]
