FROM ubuntu:22.04

# Avoid tzdata interactive prompt
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

RUN apt-get update && apt-get install -y \
    openssh-server \
    sudo \
    python3 \
    curl \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Create test user with password "test" and sudo
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:test" | chpasswd && \
    usermod -aG sudo testuser

# Allow password auth for testing
RUN sed -i 's/^#PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^#PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/^PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    echo "UseDNS no" >> /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
