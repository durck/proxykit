FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
	&& apt-get install -y --no-install-recommends krb5-admin-server krb5-kdc krb5-user \
	&& rm -rf /var/lib/apt/lists/*

COPY krb5.conf /etc/krb5.conf
COPY kdc.conf /etc/krb5kdc/kdc.conf
COPY kadm5.acl /etc/krb5kdc/kadm5.acl
COPY entrypoint.sh /usr/local/bin/proxykit-krb5-entrypoint

RUN chmod +x /usr/local/bin/proxykit-krb5-entrypoint

EXPOSE 88/tcp

ENTRYPOINT ["/usr/local/bin/proxykit-krb5-entrypoint"]
