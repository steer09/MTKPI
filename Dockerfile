FROM docker.io/tsl0922/ttyd:latest
LABEL maintainer="steer09"

EXPOSE 7681

WORKDIR /var/run

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl \
    iputils-ping \
    nano \
    python3-pip \
    dnsutils \
    apt-file \
    net-tools \
    nmap \
    stow \
    git-core \
    sudo \
    util-linux \
    p7zip-full \
    jq \
    ssh \
    python3 \
    upx \
    wget \
    xz-utils \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY ./install.sh /usr/local/bin/install.sh
RUN chmod +x /usr/local/bin/install.sh && /usr/local/bin/install.sh && rm -f /usr/local/bin/install.sh

COPY ./access_kubelet_api.py /usr/local/bin/access_kubelet_api.py
COPY ./access_kubernetes_api.py /usr/local/bin/access_kubernetes_api.py
COPY ./network_mapping.py /usr/local/bin/network_mapping.py
COPY ./credintial_access.py /usr/local/bin/credintial_access.py
COPY ./kube_bench_scan.py /usr/local/bin/kube_bench_scan.py
COPY ./peirates_attacks.py /usr/local/bin/peirates_attacks.py
COPY ./combined_recon.py /usr/local/bin/combined_recon.py
COPY ./cdk_exploitation.py /usr/local/bin/cdk_exploitation.py

# Устанавливаем права на выполнение для всех скриптов
RUN chmod +x /usr/local/bin/access_kubelet_api.py /usr/local/bin/access_kubernetes_api.py /usr/local/bin/network_mapping.py /usr/local/bin/credintial_access.py /usr/local/bin/kube_bench_scan.py /usr/local/bin/peirates_attacks.py /usr/local/bin/combined_recon.py /usr/local/bin/cdk_exploitation.py

# Указываем рабочую директорию
WORKDIR /usr/local/bin

# CMD ["ttyd", "-p", "7681", "--", "bash"]

