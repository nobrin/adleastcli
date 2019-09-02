FROM alpine:3.10.2
MAINTAINER Nobuo Okazaki <nobrin@biokids.org>
RUN apk add python3 py3-ldap3 tzdata bash \
 && cp -av /usr/share/zoneinfo/Japan /etc/localtime \
 && adduser -u 1000 -D ldap ldap
COPY adleastcli /usr/bin/adleastcli
COPY docker-entrypoint.sh /usr/bin/docker-entrypoint.sh
ENV PYTHONUNBUFFERED=1
USER ldap
EXPOSE 8080
ENTRYPOINT ["docker-entrypoint.sh"]

