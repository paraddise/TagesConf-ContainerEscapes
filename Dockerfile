# docker build -t paraddise/ubuntu .
# docker push paraddise/ubuntu

FROM ubuntu:22.04

RUN apt update && apt install -y gcc curl vim net-tools netcat-traditional libcap2-bin gdb make john ssh git tcpdump kmod
RUN curl -L -o cdk https://github.com/cdk-team/CDK/releases/download/v1.5.3/cdk_linux_amd64 && chmod +x ./cdk
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && chmod +x ./kubectl