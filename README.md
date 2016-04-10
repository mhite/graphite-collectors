# graphite-collectors

## Introduction

The graphite-collectors project is comprised of vendor-specific agents able to collect device metrics and feed them upstream to a [Graphite](https://github.com/graphite-project) server.

Currently, the only supported collector agent is the F5 BIG-IP agent. Previous collector code for Juniper SRX and MX has been removed until further notice.

## Requires

### f5-agent

The following Python dependencies are required to support F5 metric collection.

- argparse
- bigsuds

## Limitations

The graphite collector must be installed and run on a periodic basis (ie. cron) via a poller host. The collector is not designed to run on the BIG-IP device itself.

## Installation

```
git clone https://github.com/mhite/graphite-collectors.git
cd graphite-collectors
pip install .
```

This will install the required libraries into your Python installation along with `f5-agent` in the `/usr/local/bin/` directory.

## Usage

Information about the collector tool can be viewed with the ```-h``` option.

```
$ f5-agent --help
usage: f5-agent [-h] [--version]
                [--log-level {critical,error,warning,info,debug}]
                [--log-filename LOGFILE] --f5-username F5_USERNAME
                --f5-password F5_PASSWORD --f5-host F5_HOST
                [--f5-retries F5_RETRIES] [--f5-interval F5_INTERVAL]
                [--carbon-host CARBON_HOST] [-p CARBON_PORT]
                [-e {plaintext,pickle}] [-r CARBON_RETRIES]
                [-i CARBON_INTERVAL] [-c CHUNK_SIZE] [--prefix PREFIX]
                [-t {local,remote}] [-s] [--exclude PATTERN] [--no-ip]
                [--no-ipv6] [--no-icmp] [--no-icmpv6] [--no-tcp] [--no-tmm]
                [--no-client-ssl] [--no-interface] [--no-trunk] [--no-cpu]
                [--no-host] [--no-snat-pool] [--no-snat-translation]
                [--no-virtual-server] [--no-pool] [--no-pool-member]
                [--no-irule] [--no-http] [--no-oneconnect] [--no-temperature]
                [--no-fan] [--no-device-group] [--no-node]
                [--no-web-acceleration] [--no-tcp-profile]

F5 BIG-IP graphite agent

optional arguments:
  -h, --help            show this help message and exit
  --version, -v         show program's version number and exit

logging:
  --log-level {critical,error,warning,info,debug}, -l {critical,error,warning,info,debug}
                        Logging level
  --log-filename LOGFILE, -o LOGFILE
                        Logging output filename

icontrol:
  --f5-username F5_USERNAME, --f5-user F5_USERNAME
                        Username for F5 iControl authentication
  --f5-password F5_PASSWORD, --f5-pass F5_PASSWORD
                        Password for F5 iControl authentication
  --f5-host F5_HOST     F5 host
  --f5-retries F5_RETRIES
                        Number of F5 iControl connection retry attempts [2]
  --f5-interval F5_INTERVAL
                        Interval between F5 iControl connection retry attempts
                        [5]

carbon:
  --carbon-host CARBON_HOST
                        Carbon host
  -p CARBON_PORT, --carbon-port CARBON_PORT, --port CARBON_PORT
                        Carbon port
  -e {plaintext,pickle}, --carbon-encoding {plaintext,pickle}, --encoding {plaintext,pickle}
                        Carbon encoding [plaintext]
  -r CARBON_RETRIES, --carbon-retries CARBON_RETRIES
                        Number of carbon server delivery attempts [2]
  -i CARBON_INTERVAL, --carbon-interval CARBON_INTERVAL
                        Interval between carbon delivery attempts [30]
  -c CHUNK_SIZE, --chunk-size CHUNK_SIZE
                        Carbon chunk size [500]
  --prefix PREFIX       Metric name prefix [bigip.f5_host]
  -t {local,remote}, --timestamp {local,remote}
                        Timestamp authority (local | remote) [remote]
  -s, --skip-upload, -d, --dry-run
                        Skip metric upload step [False]

metric:
  --exclude PATTERN
  --no-ip
  --no-ipv6
  --no-icmp
  --no-icmpv6
  --no-tcp
  --no-tmm
  --no-client-ssl
  --no-interface
  --no-trunk
  --no-cpu
  --no-host
  --no-snat-pool
  --no-snat-translation
  --no-virtual-server
  --no-pool
  --no-pool-member
  --no-irule
  --no-http
  --no-oneconnect
  --no-temperature
  --no-fan
  --no-device-group
  --no-node
  --no-web-acceleration
  --no-tcp-profile
```

## Examples

On the server that will perform metric collection, install the following cron:

```
*/5 * * * * /usr/local/bin/f5-agent @/usr/local/etc/collector.cnf
```

This cron entry will perform metric collection against an F5 device every 5 minutes. You will need a separate configuration file and cron entry for each F5 device.

Create a configuration file in `/usr/local/etc/collector.cnf` similar to the following:

```
--f5-username
<REPLACE_WITH_F5_ADMIN_USER_ACCOUNT>
--f5-password
<REPLACE_WITH_F5_ADMIN_USER_PASSWORD>
--f5-host
<REPLACE_WITH_FULLY_QUALIFIED_F5_HOSTNAME>
--carbon-host
<REPLACE_WITH_FULLY_QUALIFIED_GRAPHITE_HOSTNAME>
--carbon-port
<REPLACE_WITH_PICKLE_PORT>
--carbon-encoding
pickle
--log-level
critical
--prefix
<REPLACE_WITH_METRIC_PREFIX>
--timestamp
remote
--no-snat-translation
--no-snat-pool
--no-node
--exclude
*.pool_member.*pva_*
--exclude
*.pool_member.*.connqueue_*
--exclude
*.pool_member.*.server_side_maximum_connections
--exclude
*.pool.*pva_*
--exclude
*.pool.*.connqueue_*
--exclude
*.system.host.*.multi_processor_mode
--exclude
*.system.host.*.cpu_count
--exclude
*.system.host.*.active_cpu_count
--exclude
*.vs.*pva_*
--exclude
*.vs.*.ephemeral_*
--exclude
*.vs.*.acl_no_match
--exclude
*.vs.*.virtual_server_five_sec_avg_cpu_usage
--exclude
*.vs.*.virtual_server_one_min_avg_cpu_usage
--exclude
*.vs.*.client_side_maximum_connections
--exclude
*.vs.*.minimum_connection_duration
--exclude
*.vs.*.maximum_connection_duration
```

The `--no` and `--exclude` arguments are portions of the metric tree that will be ignored and not send to the Graphite server.

## Author

[Matt Hite](mailto:mhite@hotmail.com) created graphite-collectors. Feel free to reach out to me with any F5 consulting and/or custom integration needs your organization may have.

## Contribute

Your code contributions are welcome. Please fork and open a pull request.

## Change Log

### 1.9.4

- TCP profile support added

### 1.9.2

- Web acceleration support added

### Prior

- See commit messages

## License

Please see [LICENSE](./LICENSE).
