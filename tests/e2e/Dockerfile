FROM alpine:3.20
RUN apk add --no-cache openssh-server openssh-keygen \
 && adduser -D -s /bin/sh wguser \
 && passwd -u wguser \
 && mkdir -p /home/wguser/.ssh /var/log/nginx \
 && for i in $(seq 1 20); do echo "2026/01/01 00:00:$i [error] fake nginx error line $i" >> /var/log/nginx/error.log; done \
 && chmod 644 /var/log/nginx/error.log \
 && chmod 700 /home/wguser/.ssh && chown wguser /home/wguser/.ssh
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
