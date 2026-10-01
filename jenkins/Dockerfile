FROM jenkins/jenkins:2.580.1-jdk25@sha256:42fc298cdafa2683dddde9a7ccdce4058f771b1ec56c2423dbfca82f010a455f

USER root

RUN apt-get update -qq && \
    apt-get upgrade -y -qq --no-install-recommends && \
    apt-get install -y -qq --no-install-recommends ca-certificates curl gnupg python3 && \
    install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | \
      gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    chmod a+r /etc/apt/keyrings/docker.gpg && \
    . /etc/os-release && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
      https://download.docker.com/linux/debian ${VERSION_CODENAME} stable" \
      > /etc/apt/sources.list.d/docker.list && \
    apt-get update -qq && \
    apt-get install -y -qq docker-ce-cli && \
    apt-get purge -y -qq openssh-client && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/*

USER jenkins

COPY --chown=jenkins:jenkins plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt --latest=false

HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
    CMD curl --fail --silent --max-time 5 http://127.0.0.1:8080/jenkins/login > /dev/null || exit 1
