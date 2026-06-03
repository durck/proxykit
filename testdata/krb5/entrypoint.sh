#!/bin/sh
set -eu

realm="${KRB5_REALM:-PROXYKIT.TEST}"
client="${KRB5_CLIENT:-alice}"
client_password="${KRB5_CLIENT_PASSWORD:-alice-password}"
service_principal="${KRB5_SERVICE_PRINCIPAL:-HTTP/proxy.proxykit.test}"

mkdir -p /var/lib/krb5kdc /var/log/krb5kdc /out

if [ ! -f /var/lib/krb5kdc/principal ]; then
	kdb5_util create -s -r "$realm" -P master-password
fi

kadmin.local -r "$realm" -q "addprinc -pw $client_password $client@$realm" >/dev/null 2>&1 || true
kadmin.local -r "$realm" -q "addprinc -randkey $service_principal@$realm" >/dev/null 2>&1 || true

rm -f /out/proxy.keytab
kadmin.local -r "$realm" -q "ktadd -k /out/proxy.keytab $service_principal@$realm" >/dev/null
chmod 0644 /out/proxy.keytab

exec krb5kdc -n -r "$realm" -P /run/krb5kdc.pid
