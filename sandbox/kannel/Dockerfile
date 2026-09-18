FROM redhat/ubi10:10.1 AS builder

RUN yum update -y &&\
    yum install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-10-x86_64/pgdg-redhat-repo-latest.noarch.rpm &&\
    yum install -y gcc libxml2-devel openssl openssl-devel automake libtool postgresql15-libs &&\
    # bootstrap mis-detects the automake version, so we masquerade as 1.11
    ln -s /usr/bin/automake /usr/bin/automake-1.11 &&\
    ln -s /usr/bin/aclocal /usr/bin/aclocal-1.11 &&\
    curl -o postgresql15-devel-15.15-1PGDG.rhel10.x86_64.rpm https://download.postgresql.org/pub/repos/yum/15/redhat/rhel-10.1-x86_64/postgresql15-devel-15.15-1PGDG.rhel10.x86_64.rpm &&\
    rpm -ivh --nodeps postgresql15-devel-15.15-1PGDG.rhel10.x86_64.rpm &&\
    ln -s /usr/pgsql-15 /usr/local/pgsql &&\
    curl -k -o gateway.tgz https://www.kannel.org/download/1.5.0/gateway-1.5.0.tar.gz &&\
    tar -zxvf gateway.tgz &&\
    cd gateway-1.5.0 &&\
    ./configure --prefix=/usr/local/kannel --with-pgsql CFLAGS="-fcommon" &&\
    make &&\
    make install &&\
    cp test/fakesmsc /usr/local/kannel/sbin &&\
    cd addons/opensmppbox &&\
    ./bootstrap &&\
    ./configure --prefix=/usr/local/kannel --with-kannel-dir=../.. &&\
    make &&\
    make install &&\
    cd ../.. &&\
    cd addons/sqlbox &&\
    ./bootstrap &&\
    ./configure --prefix=/usr/local/kannel --with-kannel-dir=../.. CFLAGS="-Wno-implicit-function-declaration" &&\
    make &&\
    make install &&\
    cd ../..

FROM redhat/ubi10-minimal:10.1

RUN microdnf update -y &&\
    microdnf install -y openldap &&\
    curl -o /tmp/postgresql15-libs-15.17-1PGDG.rhel10.1.x86_64.rpm "https://download.postgresql.org/pub/repos/yum/15/redhat/rhel-10.1-x86_64/postgresql15-libs-15.17-1PGDG.rhel10.1.x86_64.rpm" &&\
    rpm -i /tmp/postgresql15-libs-15.17-1PGDG.rhel10.1.x86_64.rpm &&\
    rm /tmp/postgresql15-libs-15.17-1PGDG.rhel10.1.x86_64.rpm &&\
    microdnf clean all

COPY --from=builder /usr/local/kannel /usr/local/kannel

VOLUME [/etc/kannel, /var/log/kannel]