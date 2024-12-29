#!/bin/bash
set -e

# Install Python 2 if missing
apt-get update && apt-get install -y python2
ln -sf /usr/bin/python2 /usr/bin/python

# Install botb
curl -LO https://github.com/brompwnie/botb/releases/download/1.8.0/botb-linux-amd64 \
    && install botb-linux-amd64 /usr/local/bin/botb \
    && rm -rf botb-linux-amd64

# Install traitor
curl -LO https://github.com/liamg/traitor/releases/download/v0.0.14/traitor-amd64 \
    && install traitor-amd64 /usr/local/bin/traitor \
    && rm -rf traitor-amd64

# Install kubeletctl
curl -LO https://github.com/cyberark/kubeletctl/releases/download/v1.12/kubeletctl_linux_amd64 \
    && install kubeletctl_linux_amd64 /usr/local/bin/kubeletctl \
    && rm -rf kubeletctl_linux_amd64

# Install kubesploit
curl -LO https://github.com/cyberark/kubesploit/releases/download/v0.1.3/kubesploitAgent-Linux-x64.7z \
    && 7z x kubesploitAgent-Linux-x64.7z -p"kubesploit" -o/tmp/kubesploit \
    && mv /tmp/kubesploit/kubesploitAgent-Linux-x64 /usr/local/bin/kubesploit \
    && chmod +x /usr/local/bin/kubesploit \
    && rm -rf /tmp/kubesploit kubesploitAgent-Linux-x64.7z

# Install CDK
curl -LO https://github.com/cdk-team/CDK/releases/download/v1.5.3/cdk_linux_amd64 \
    && install cdk_linux_amd64 /usr/local/bin/cdk \
    && rm -rf cdk_linux_amd64

# Install peirates
curl -L https://github.com/inguardians/peirates/releases/download/v1.1.23/peirates-linux-amd64.tar.xz \
    | tar -xJ -C /usr/local/bin --strip-components=1 peirates-linux-amd64/peirates \
    && chmod +x /usr/local/bin/peirates

# Install ctrsploit
curl -LO https://github.com/ctrsploit/ctrsploit/releases/download/v0.5.15/ctrsploit_linux_amd64 \
    && install ctrsploit_linux_amd64 /usr/local/bin/ctrsploit \
    && rm -rf ctrsploit_linux_amd64

# Install kdigger
curl -LO https://github.com/quarkslab/kdigger/releases/download/v1.5.1/kdigger-linux-amd64 \
    && install kdigger-linux-amd64 /usr/local/bin/kdigger \
    && rm -rf kdigger-linux-amd64

# Install kubectl
curl -LO "https://dl.k8s.io/release/v1.31.3/bin/linux/amd64/kubectl" \
    && chmod +x kubectl && mv kubectl /usr/local/bin/

# Install amicontained
curl -LO https://github.com/genuinetools/amicontained/releases/download/v0.4.9/amicontained-linux-amd64 \
    && install amicontained-linux-amd64 /usr/local/bin/amicontained \
    && rm -rf amicontained-linux-amd64

# Install linuxprivchecker NOW WORKING
curl -LO https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py \
    && mv linuxprivchecker.py /usr/local/bin/linuxprivchecker.py \
    && chmod +x /usr/local/bin/linuxprivchecker.py

# Install unix-privesc-checker NOW IT'S NOT WORKING, MAKE SOME RETRY LATER
#curl -L http://pentestmonkey.net/tools/unix-privesc-check/unix-privesc-check-1.4.tar.gz \
#    | tar -xz -C /usr/local/bin --strip-components=1 unix-privesc-check*/unix-privesc-check

# Install deepce
curl -LO https://raw.githubusercontent.com/stealthcopter/deepce/main/deepce.sh \
    && chmod +x deepce.sh && mv deepce.sh /usr/local/bin/deepce

# Install helm
curl https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash

# Install kube-hunter CURRENTLY NOT WORKING
#curl -LO https://github.com/aquasecurity/kube-hunter/releases/download/v0.6.8/kube-hunter-linux-x86_64-refs.tags.v0.6.8 \
    #&& mv kube-hunter-linux-x86_64-refs.tags.v0.6.8 /usr/local/bin/kube-hunter && chmod +x /usr/local/bin/kube-hunter
   
# Install kube-hunter NEWx2 ACTUAL VERSION
#curl -LO https://github.com/aquasecurity/kube-hunter/releases/download/v0.6.8/kube-hunter-linux-x86_64-refs.tags.v0.6.8 \
    #&& mv kube-hunter-linux-x86_64-refs.tags.v0.6.8 /usr/local/bin/kube-hunter \
    #&& chmod +x /usr/local/bin/kube-hunter

# Install kube-hunter via pip NEW COMMIT
apt-get update && apt-get install -y python3 python3-pip
pip3 install kube-hunter 

apt-get update && apt-get install -y python3 python3-pip
pip3 install kube-hunter

# Установить размер стека потоков для Python
echo "import threading; threading.stack_size(256*1024)" >> /usr/local/lib/python3.8/dist-packages/kube_hunter/__main__.py

# Настроить количество потоков по умолчанию
sed -i "s/handler = EventQueue(config.num_worker_threads)/handler = EventQueue(2)/" /usr/local/lib/python3.8/dist-packages/kube_hunter/core/events/event_handler.py

# Install kubescape
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | bash

# Install kube-bench
curl -LO https://github.com/aquasecurity/kube-bench/releases/download/v0.8.0/kube-bench_0.8.0_linux_amd64.deb \
    && dpkg -i kube-bench_0.8.0_linux_amd64.deb && rm kube-bench_0.8.0_linux_amd64.deb

# Install etcdctl
curl -LO https://github.com/etcd-io/etcd/releases/download/v3.3.13/etcd-v3.3.13-linux-amd64.tar.gz \
    && tar -xzvf etcd-v3.3.13-linux-amd64.tar.gz && mv etcd-v3.3.13-linux-amd64/etcdctl /usr/local/bin/ \
    && chmod +x /usr/local/bin/etcdctl && rm -rf etcd-v3.3.13-linux-amd64 etcd-v3.3.13-linux-amd64.tar.gz
    
# Install DDexec with dependency check
apt-get update && apt-get install -y coreutils procps gawk

# Install DDexec
curl -LO https://raw.githubusercontent.com/arget13/DDexec/main/ddexec.sh \
    && chmod +x ddexec.sh && mv ddexec.sh /usr/local/bin/ddexec

# Install kubetcd
curl -LO https://github.com/nccgroup/kubetcd/releases/download/v1.28/kubetcd_linux_amd64 \
    && mv kubetcd_linux_amd64 /usr/local/bin/kubetcd && chmod +x /usr/local/bin/kubetcd

# Install k8spider
curl -LO https://github.com/Esonhugh/k8spider/releases/download/v2.4.0/k8spider_v2.4.0_linux_amd64.tar.gz \
    && tar -xzvf k8spider_v2.4.0_linux_amd64.tar.gz && mv k8spider /usr/local/bin/ \
    && chmod +x /usr/local/bin/k8spider && rm -rf k8spider_v2.4.0_linux_amd64.tar.gz

# Clean up
apt-get clean

