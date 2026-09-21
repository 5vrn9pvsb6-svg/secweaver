FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai

RUN apt-get update && apt-get install -y \
    openssh-server \
    rsyslog \
    sudo \
    curl \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd

# SSH: allow password auth
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    ssh-keygen -A

# Target user with weak password
RUN useradd -m -s /bin/bash devops && \
    echo 'devops:devops123' | chpasswd && \
    usermod -aG sudo devops

# Sensitive data (attack objective)
RUN mkdir -p /home/devops/projects /home/devops/.config
COPY data/db-credentials.conf /home/devops/projects/
COPY data/deploy-token.json   /home/devops/.config/
RUN chown -R devops:devops /home/devops && \
    chmod 600 /home/devops/projects/db-credentials.conf \
              /home/devops/.config/deploy-token.json

COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 22
CMD ["/start.sh"]
