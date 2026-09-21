FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai

RUN apt-get update && apt-get install -y \
    nginx \
    php-fpm \
    php-cli \
    sshpass \
    openssh-client \
    iputils-ping \
    net-tools \
    iproute2 \
    nmap \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# PHP-FPM: enable dangerous functions (intentionally vulnerable)
RUN PHP_INI=$(find /etc/php -name php.ini -path "*/fpm/*" | head -1) && \
    sed -i 's/^disable_functions =.*/disable_functions =/' "$PHP_INI" && \
    sed -i 's/^upload_max_filesize =.*/upload_max_filesize = 10M/' "$PHP_INI" && \
    sed -i 's/^post_max_size =.*/post_max_size = 12M/' "$PHP_INI"

# PHP-FPM: listen on TCP 9000
RUN PHP_POOL=$(find /etc/php -name www.conf -path "*/pool.d/*" | head -1) && \
    sed -i 's|^listen = .*|listen = 127.0.0.1:9000|' "$PHP_POOL"

COPY nginx.conf /etc/nginx/sites-available/default

# SSH client: skip host key checking in lab
RUN mkdir -p /etc/ssh/ssh_config.d && \
    printf 'Host *\n    StrictHostKeyChecking no\n    UserKnownHostsFile /dev/null\n    LogLevel ERROR\n' \
    > /etc/ssh/ssh_config.d/lab.conf

COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 80
CMD ["/start.sh"]
