Zabbix proxy is a process that may collect monitoring data from one or more monitored devices and send the information to the Zabbix server, essentially working on behalf of the server. All collected data is buffered locally and then transferred to the Zabbix server the proxy belongs to.

Deploying a proxy is optional, but may be very beneficial to distribute the load of a single Zabbix server. If only proxies collect data, processing on the server becomes less CPU and disk I/O hungry.

A Zabbix proxy is the ideal solution for centralized monitoring of remote locations, branches and networks with no local administrators.

Zabbix proxy requires a separate database.

# ansible-zabbix_proxy

Zabbix proxy is deployed on a monitoring target to actively monitor local
resources and applications (hard drives, memory, processor statistics etc).

## Requirements

* Ansible 3.0.0+;

## Example configuration

```yaml
---
zabbix_proxy:
# Enable zabbix-proxy service or not.
- enable: 'true'
# Restart zabbix-proxy service or not.
  restart: 'true'
# Install/upgrade zabbix-proxy package or not
  install_package: 'true'
# 'present' (do nothing if package is already installed) or 'latest' (always
# upgrade to last version)
  package_state: 'latest'
# Pre-shared key string.
  psk_string: '42a46dc13aff1bc26ba2467779da343614a8bbf1c39780c9819cf24e32d8f279'
# Deploy or not 'psk_string' as '/etc/zabbix/zabbix_proxy.psk' file.
  deploy_psk_file: 'true'
  settings:
#   Proxy operating mode.
#   0 - proxy in the active mode (default)
#   1 - proxy in the passive mode
  - proxymode: '0'
#   If ProxyMode is set to active mode:
# IP address or DNS name (address:port) or cluster (address:port;address2:port) of Zabbix server to get configuration data from and send data to.
# If port is not specified, default port is used.
# Cluster nodes need to be separated by semicolon.
#   If ProxyMode is set to passive mode:
# List of comma delimited IP addresses, optionally in CIDR notation, or DNS names of Zabbix server.
# Incoming connections will be accepted only from the addresses listed here.
# If IPv6 support is enabled then '127.0.0.1', '::127.0.0.1', '::ffff:127.0.0.1' are treated equally
# and '::/0' will allow any IPv4 or IPv6 address.
# '0.0.0.0/0' can be used to allow any IPv4 address.
# Example: Server=127.0.0.1,192.168.1.0/24,::1,2001:db8::/32,zabbix.example.com
    server: 
    - '127.0.0.1'
    - '192.168.1.0/24'
    - '::1'
    - '2001:db8::/32'
    - 'zabbix.example.com'
#	Unique, case sensitive hostname. Required for active checks and must match
# hostname as configured on the server. Value is acquired from HostnameItem if
# undefined.
    hostname: 'r1.example.com'
#	Item used for generating Hostname if it is undefined. Ignored if Hostname is
# defined. Does not support 'user_parameter' or aliases.
    hostname_item: 'system.hostname'
#	Listen port for trapper.
# Default is '10051'.
    listen_port: '10051'
    log_type: 'system'
#	Log file name for LogType 'file' parameter. Mandatory if 'log_type' is set to
# 'file'.
    log_file: '/var/log/zabbix_proxy.log'
#	Maximum size of log file in range 0-1024MB. '0' - disable automatic log
# rotation. Default is '1'.
    log_file_size: '1'
#	Specifies debug level:
#	'0' - basic information about starting and stopping of Zabbix processes;
#	'1' - critical information;
#	'2' - error information;
#	'3' - warnings (the default);
#	'4' - for debugging (produces lots of information);
#	'5' - extended debugging (produces even more information);
    debug_level: '3'
#	Source IP address for outgoing connections.
    source_ip: ''
#	Whether remote commands from Zabbix server are allowed.
# '0' - not allowed (the default);
# '1' - allowed;
    enable_remote_commands: '0'
#	Enable logging of executed shell commands as warnings.
# '0' - disabled (the default);
# '1' - enabled;
    log_remote_commands: '0'
#	Name of PID file.
    pid_file: 'tmp/zabbix_proxy.pid'
#   IPC socket directory.
# Directory to store IPC sockets used by internal Zabbix services.
    socket_dir: '/run/zabbix-proxy'
#   Database host name.
# If set to localhost, socket is used for MySQL.
# If set to empty string, socket is used for PostgreSQL.
# Default: comment options
    db_host: 'localhost'
#   Database name.
# For SQLite3 path to database file must be provided. DBUser and DBPassword are ignored.
# Warning: do not attempt to use the same database Zabbix server is using.
    db_name: /var/lib/zabbix-proxy/zabbix_proxy
#   Database user. Ignored for SQLite.
    db_user: 'zabbix'
#   Database password. Ignored for SQLite.
# Comment this line if no password is used.
    db_password: 'somepassword'
#   Path to MySQL socket.
    db_socket: /var/run/mysql.run'
#	Spend no more than timeout seconds (in range 1-30) on processing.
# Default is '4'.
    timeout: '4'
#   How long a database query may take before being logged (in milliseconds).
# Only works if DebugLevel set to 3 or 4.
# 0 - don't log slow queries.
    log_slow_query: '3000'
#   You may include individual files or all files in a directory in the configuration file.
# Installing Zabbix will create include directory in /usr/local/etc, unless modified during the compile time.
    include:
    - '/etc/zabbix_proxy.general.conf'
    - '/etc/zabbix_proxy.conf.d/'
    - '/etc/zabbix_proxy.conf.d/*.conf'
#   List of comma delimited IP addresses, optionally in CIDR notation, or DNS names of external Zabbix instances.
# Stats request will be accepted only from the addresses listed here. If this parameter is not set no stats requests
# will be accepted.
# If IPv6 support is enabled then '127.0.0.1', '::127.0.0.1', '::ffff:127.0.0.1' are treated equally
# and '::/0' will allow any IPv4 or IPv6 address.
# '0.0.0.0/0' can be used to allow any IPv4 address.
# Example: StatsAllowedIP=127.0.0.1,192.168.1.0/24,::1,2001:db8::/32,zabbix.example.com
    stats_ip: 
    - '127.0.0.1'
    - '192.168.1.0/24'
    - '::1'
    - '2001:db8::/32'
    - 'zabbix.example.com'
#	How the proxy should connect to server or proxy. Used for active checks. Only
# one value can be specified:
#	'unencrypted' - connect without encryption (the default);
#	'psk' - connect using TLS and a pre-shared key;
#	'cert' - connect using TLS and a certificate;
# This option is mandatory, if TLS certificate or PSK parameters are defined
# (even for 'unencrypted' connection).
    tls_connect: 'unencrypted'
#	What incoming connections to accept. Multiple values can be specified:
#	'unencrypted' - accept connections without encryption (the default);
#	'psk' - accept connections secured with TLS and a pre-shared key;
#	'cert' - accept connections secured with TLS and a certificate;
# This options is mandatory, if TLS certificate or PSK parameters are defined
# (even for 'unencrypted' connection)
    tls_accept: 'unencrypted'
#	Full pathname of a file containing the top-level CA certificates for peer
# certificate verification. Default is None.
    tls_ca_file: ''
#	Full pathname of a file containing revoked certificates. Default is None.
    tls_crl_file: ''
# Allowed server certificate issuer. Default is None.
    tls_server_cert_issuer: ''
#	Allowed server certificate subject. Default is None.
    tls_server_cert_subject: ''
#	Full pathname of a file containing the proxy certificate or certificate chain.
# Default is None.
    tls_cert_file: ''
#	Full pathname of a file containing the proxy private key. Default is None.
    tls_key_file: ''
#	Unique, case sensitive string used to identify the pre-shared key. Default
# is None.
    tls_psk_identity: 'psk 001'
#	Full pathname of a file containing the pre-shared key. Default is None.
    tls_psk_file: '/etc/zabbix/zabbix_proxy.psk'
```