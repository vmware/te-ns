apt-get purge -y postgresql
apt-get install -y wget
wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add -
sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt/ xenial-pgdg main" > /etc/apt/sources.list.d/PostgreSQL.list'
apt-get update
apt-get install -y postgresql-11
sed -i "s/peer/trust/g" /etc/postgresql/*/main/pg_hba.conf


gpasswd -a postgres ssl-cert
chown root:ssl-cert  /etc/ssl/private/ssl-cert-snakeoil.key
chmod 740 /etc/ssl/private/ssl-cert-snakeoil.key