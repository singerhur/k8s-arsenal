FROM python:3.11-slim
WORKDIR /app

# 换 apt 源为清华镜像 + 装系统工具 + kubectl
RUN sed -i 's|http://deb.debian.org|https://mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl procps net-tools iproute2 docker.io && \
    rm -rf /var/lib/apt/lists/*

# 下载 kubectl（与 minikube K8s v1.35.1 匹配）
RUN curl -fsSLo /usr/local/bin/kubectl https://dl.k8s.io/release/v1.35.1/bin/linux/amd64/kubectl && \
    chmod +x /usr/local/bin/kubectl

# 安装 k8s-arsenal（用清华 PyPI 镜像）
COPY k8s_arsenal/ /app/k8s_arsenal/
COPY pyproject.toml /app/
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple /app/

CMD ["sleep", "infinity"]
