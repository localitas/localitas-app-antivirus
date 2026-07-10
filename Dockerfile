FROM debian:12-slim

RUN apt-get update -qq && \
    apt-get install -y -qq ca-certificates clamav clamav-daemon && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /var/run/clamav /var/lib/clamav && \
    chown -R clamav:clamav /var/run/clamav /var/lib/clamav && \
    sed -i 's/^Example/#Example/' /etc/clamav/clamd.conf && \
    sed -i 's/^Example/#Example/' /etc/clamav/freshclam.conf && \
    freshclam --quiet || true

RUN useradd --system --no-create-home --shell /usr/sbin/nologin app || true
RUN usermod -aG clamav app || true

COPY antivirus-server-linux-amd64 /usr/local/bin/app-server
RUN chmod +x /usr/local/bin/app-server

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
