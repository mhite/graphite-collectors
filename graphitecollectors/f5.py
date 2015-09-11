#!/usr/bin/python

# Author: Matt Hite
# Email: mhite@hotmail.com

import argparse
import bigsuds
import httplib
import json
import logging
import sys
import time
import traceback
from carbonita import Carbon, timestamp_local
from datetime import tzinfo, timedelta, datetime
from fnmatch import fnmatchcase
from pprint import pformat

__VERSION__ = "1.83"


def get_parser():
    """Generates an argparse parser.

    Returns:
        An instantiated argparse parser object.
    """
    parser = argparse.ArgumentParser(description="F5 BIG-IP graphite agent",
                                     fromfile_prefix_chars='@')
    parser.add_argument('--version', action='version', version=__VERSION__)
    log_group = parser.add_argument_group('logging')
    log_group.add_argument('--log-level', '-l', help='Logging level',
                           choices=('critical', 'error', 'warning', 'info',
                                    'debug'),
                           dest='loglevel',
                           default='critical')
    log_group.add_argument('--log-filename', '-o',
                           help='Logging output filename',
                           action='store', dest='logfile')
    icontrol_group = parser.add_argument_group('icontrol')
    icontrol_group.add_argument('--f5-username', '--f5-user',
                                help='Username for F5 iControl authentication',
                                dest='f5_username', required=True)
    icontrol_group.add_argument('--f5-password', '--f5-pass',
                                help='Password for F5 iControl authentication',
                                dest='f5_password', required=True)
    icontrol_group.add_argument('--f5-host', help="F5 host", dest="f5_host",
                                required=True)
    icontrol_group.add_argument('--f5-retries', help="Number of F5 iControl " +
                                "metric collection attempts [%(default)d]",
                                type=int, dest="f5_retries", default=2)
    icontrol_group.add_argument('--f5-interval', help="Interval between F5 " +
                                "iControl metric collection retry attempts " +
                                "[%(default)d]", type=int, dest="f5_interval",
                                default=5)
    carbon_group = parser.add_argument_group('carbon')
    carbon_group.add_argument('--carbon-host', help="Carbon host",
                              dest="carbon_host")
    carbon_group.add_argument('-p', '--carbon-port', '--port',
                              help="Carbon port", type=int,
                              dest='carbon_port')
    carbon_group.add_argument('-e', '--carbon-encoding', '--encoding',
                              help="Carbon encoding [%(default)s]",
                              default='plaintext', dest='carbon_encoding',
                              choices=['plaintext', 'pickle'])
    carbon_group.add_argument('-r', '--carbon-retries',
                              help="Number of carbon server delivery " +
                                   "attempts [%(default)d]", type=int,
                              dest="carbon_retries", default=2)
    carbon_group.add_argument('-i', '--carbon-interval',
                              help="Interval between carbon delivery " +
                                   "attempts [%(default)d]", type=int,
                              dest="carbon_interval", default=30)
    carbon_group.add_argument('-c', '--chunk-size',
                              help='Carbon chunk size [%(default)d]',
                              type=int, dest='chunk_size', default=500)
    carbon_group.add_argument('--prefix',
                              help="Metric name prefix [bigip.f5_host]",
                              dest="prefix")
    carbon_group.add_argument('-t', '--timestamp',
                              help="Timestamp authority (local | remote) " +
                                   "[%(default)s]", dest="ts_auth",
                              choices=['local', 'remote'], default="local")
    carbon_group.add_argument('-s', '--skip-upload', '-d', '--dry-run',
                              help="Skip metric upload step [%(default)s]",
                              action="store_true", dest="skip_upload",
                              default=False)
    metric_group = parser.add_argument_group('metric')
    metric_group.add_argument('--exclude', action="append", dest="exclude",
                              metavar="PATTERN")
    metric_group.add_argument('--no-ip', action="store_true", dest="no_ip")
    metric_group.add_argument('--no-ipv6', action="store_true", dest="no_ipv6")
    metric_group.add_argument('--no-icmp', action="store_true", dest="no_icmp")
    metric_group.add_argument('--no-icmpv6', action="store_true",
                              dest="no_icmpv6")
    metric_group.add_argument('--no-tcp', action="store_true", dest="no_tcp")
    metric_group.add_argument('--no-tmm', action="store_true", dest="no_tmm")
    metric_group.add_argument('--no-client-ssl', action="store_true",
                              dest="no_client_ssl")
    metric_group.add_argument('--no-interface', action="store_true",
                              dest="no_interface")
    metric_group.add_argument('--no-trunk', action="store_true",
                              dest="no_trunk")
    metric_group.add_argument('--no-cpu', action="store_true",
                              dest="no_cpu")
    metric_group.add_argument('--no-host', action="store_true",
                              dest="no_host")
    metric_group.add_argument('--no-snat-pool', action="store_true",
                              dest="no_snat_pool")
    metric_group.add_argument('--no-snat-translation', action="store_true",
                              dest="no_snat_translation")
    metric_group.add_argument('--no-virtual-server', action="store_true",
                              dest="no_virtual_server")
    metric_group.add_argument('--no-pool', action="store_true", dest="no_pool")
    metric_group.add_argument('--no-pool-member', action="store_true",
                              dest="no_pool_member")
    metric_group.add_argument('--no-irule', action="store_true",
                              dest="no_irule")
    metric_group.add_argument('--no-http', action="store_true",
                              dest="no_http")
    metric_group.add_argument('--no-oneconnect', action="store_true",
                              dest="no_oneconnect")
    metric_group.add_argument('--no-temperature', action="store_true",
                              dest="no_temperature")
    metric_group.add_argument('--no-fan', action="store_true", dest="no_fan")
    metric_group.add_argument('--no-device-group', action="store_true",
                              dest="no_device_group")
    metric_group.add_argument('--no-node', action="store_true", dest="no_node")
    return parser


class TZFixedOffset(tzinfo):
    """Fixed offset in minutes east from UTC."""

    def __init__(self, offset, name):
        self.__offset = timedelta(minutes=offset)
        self.__name = name

    def utcoffset(self, dt):
        return self.__offset

    def tzname(self, dt):
        return self.__name

    def dst(self, dt):
        return timedelta(0)


def convert_to_64_bit(high, low):
    """Converts two 32 bit signed integers to a 64-bit unsigned integer.

    Args:
        high: 32-bit signed integer representing the higher order bits
        low: 32-bit signed integer representing the lower order bits

    Returns:
        Unsigned integer value.
    """
    if high < 0:
        high = high + (1 << 32)
    if low < 0:
        low = low + (1 << 32)
    value = long((high << 32) | low)
    assert(value >= 0)
    return value


def convert_to_epoch(year, month, day, hour, minute, second, tz):
    """Converts date/time components to an epoch timestamp.

    Given a year, month, day, hour, minute, second, and timezone,
    converts to an epoch timestamp.

    Args:
        year: Integer representation of the year.
        month: Integer representation of the month.
        day: Integer representation of the day.
        hour: Integer representation of the hour.
        minute: Integer representation of the minute.
        second: Integer representation of the second.
        tz: Timezone data type.

    Returns:
        Integer value representing an epoch timestamp.
    """
    dt = datetime(year, month, day, hour, minute, second, tzinfo=tz)
    logging.debug("dt = %s" % dt)
    td = dt - datetime(1970, 1, 1, tzinfo=TZFixedOffset(0, "UTC"))
    logging.debug("td = %s" % td)
    epoch = td.seconds + td.days * 24 * 3600
    logging.debug("epoch = %s" % epoch)
    return(epoch)


def generate_timestamp(use_remote_ts, remote_ts, remote_tz):
    """Calculates epoch timestamp.

    Generate epoch timestamp from either the local system or
    the remote load balancer.

    Args:
        use_remote_ts: Boolean value indicating whether to generate the
            epoch timestamp based upon the remote load balancer or the
            local machine timestamp.
        remote_ts: Remote timestamp data structure as gathered from the F5
            API. Data structure is in the following format:
            {'day': 31,
             'hour': 20,
             'minute': 43,
             'month': 8,
             'second': 50,
             'year': 2015}
        remote_tz: Time zone data structure as returned from TZFixedOffset
            function.

    Returns:
        Integer value representing an epoch timestamp.
    """
    if use_remote_ts:
        logging.info("Calculating epoch time from remote timestamp...")
        now = convert_to_epoch(remote_ts['year'], remote_ts['month'],
                               remote_ts['day'], remote_ts['hour'],
                               remote_ts['minute'], remote_ts['second'],
                               remote_tz)
        logging.debug("Remote timestamp is %s." % now)
    else:
        now = timestamp_local()
        logging.debug("Local timestamp is %s." % now)
    return now


def parse_statistic(statistic):
    stat_name = statistic['type'].split("STATISTIC_")[-1].lower()
    high = statistic['value']['high']
    low = statistic['value']['low']
    stat_val = convert_to_64_bit(high, low)
    return (stat_name, stat_val)


def gather_f5_metrics(ltm_host, user, password, retries, interval, prefix,
                      remote_ts, no_ip, no_ipv6, no_icmp, no_icmpv6, no_tcp,
                      no_tmm, no_client_ssl, no_interface, no_trunk, no_cpu,
                      no_host, no_snat_pool, no_snat_translation,
                      no_virtual_server, no_pool, no_pool_member, no_irule,
                      no_http, no_oneconnect, no_temperature, no_fan,
                      no_device_group, no_node):
    """Connects to an F5 via iControl and pulls statistics.
    """
    last_detail = None
    now = None
    remote_tz = TZFixedOffset(0, "UTC")
    upload_attempts = 0
    upload_success = False
    max_attempts = retries + 1
    while not upload_success and (upload_attempts < max_attempts):
        metric_list = []
        upload_attempts += 1
        try:
            logging.info("Connecting to BIG-IP and pulling statistics " +
                         "(try #%d/%d)..." % (upload_attempts, max_attempts))
            b = bigsuds.BIGIP(hostname=ltm_host, username=user,
                              password=password)
            logging.info("Requesting session...")
            b = b.with_session_id()
            logging.info("Setting recursive query state to enabled...")
            b.System.Session.set_recursive_query_state(state='STATE_ENABLED')
            logging.info("Switching active folder to root...")
            b.System.Session.set_active_folder(folder="/")

            # IP

            if not no_ip:
                logging.info("Retrieving global IP statistics...")
                ip_stats = b.System.Statistics.get_ip_statistics()
                logging.debug("ip_stats =\n%s" % pformat(ip_stats))
                statistics = ip_stats['statistics']
                ts = ip_stats['time_stamp']
                now = generate_timestamp(use_remote_ts=remote_ts, remote_ts=ts,
                                         remote_tz=remote_tz)
                for y in statistics:
                    stat_name, stat_val = parse_statistic(statistic=y)
                    stat_path = "%s.protocol.ip.%s" % (prefix, stat_name)
                    metric = (stat_path, (now, stat_val))
                    logging.debug("metric = %s" % str(metric))
                    metric_list.append(metric)
            else:
                logging.debug("Skipping IP...")

            # IPv6

            if not no_ipv6:
                logging.info("Retrieving global IPv6 statistics...")
                ipv6_stats = b.System.Statistics.get_ipv6_statistics()
                logging.debug("ipv6_stats =\n%s" % pformat(ipv6_stats))
                statistics = ipv6_stats['statistics']
                ts = ipv6_stats['time_stamp']
                now = generate_timestamp(use_remote_ts=remote_ts, remote_ts=ts,
                                         remote_tz=remote_tz)
                for y in statistics:
                    stat_name, stat_val = parse_statistic(statistic=y)
                    stat_path = "%s.protocol.ipv6.%s" % (prefix, stat_name)
                    metric = (stat_path, (now, stat_val))
                    logging.debug("metric = %s" % str(metric))
                    metric_list.append(metric)
            else:
                logging.debug("Skipping IPv6...")

            # ICMP

            if not no_icmp:
                logging.info("Retrieving global ICMP statistics...")
                icmp_stats = b.System.Statistics.get_icmp_statistics()
                logging.debug("icmp_stats =\n%s" % pformat(icmp_stats))
                statistics = icmp_stats['statistics']
                ts = icmp_stats['time_stamp']
                now = generate_timestamp(use_remote_ts=remote_ts, remote_ts=ts,
                                         remote_tz=remote_tz)
                for y in statistics:
                    stat_name, stat_val = parse_statistic(statistic=y)
                    stat_path = "%s.protocol.icmp.%s" % (prefix, stat_name)
                    metric = (stat_path, (now, stat_val))
                    logging.debug("metric = %s" % str(metric))
                    metric_list.append(metric)
            else:
                logging.debug("Skipping ICMP...")

            # ICMPv6

            if not no_icmpv6:
                logging.info("Retrieving global ICMPv6 statistics...")
                icmpv6_stats = b.System.Statistics.get_icmpv6_statistics()
                logging.debug("icmpv6_stats =\n%s" % pformat(icmpv6_stats))
                statistics = icmpv6_stats['statistics']
                ts = icmpv6_stats['time_stamp']
                now = generate_timestamp(use_remote_ts=remote_ts, remote_ts=ts,
                                         remote_tz=remote_tz)
                for y in statistics:
                    stat_name, stat_val = parse_statistic(statistic=y)
                    stat_path = "%s.protocol.icmpv6.%s" % (prefix, stat_name)
                    metric = (stat_path, (now, stat_val))
                    logging.debug("metric = %s" % str(metric))
                    metric_list.append(metric)
            else:
                logging.debug("Skipping ICMPv6...")

            # TCP

            if not no_tcp:
                logging.info("Retrieving TCP statistics...")
                tcp_stats = b.System.Statistics.get_tcp_statistics()
                logging.debug("tcp_stats =\n%s" % pformat(tcp_stats))
                statistics = tcp_stats['statistics']
                ts = tcp_stats['time_stamp']
                now = generate_timestamp(use_remote_ts=remote_ts, remote_ts=ts,
                                         remote_tz=remote_tz)
                for y in statistics:
                    stat_name, stat_val = parse_statistic(statistic=y)
                    stat_path = "%s.protocol.tcp.%s" % (prefix, stat_name)
                    metric = (stat_path, (now, stat_val))
                    logging.debug("metric = %s" % str(metric))
                    metric_list.append(metric)
            else:
                logging.debug("Skipping TCP...")

            # Global TMM

            if not no_tmm:
                logging.info("Retrieving global TMM statistics...")
                global_tmm_stats = b.System.Statistics.get_global_tmm_statistics()
                logging.debug("global_tmm_stats =\n%s" % pformat(global_tmm_stats))
                statistics = global_tmm_stats['statistics']
                ts = global_tmm_stats['time_stamp']
                now = generate_timestamp(use_remote_ts=remote_ts, remote_ts=ts,
                                         remote_tz=remote_tz)
                for y in statistics:
                    stat_name, stat_val = parse_statistic(statistic=y)
                    stat_path = "%s.tmm.global.%s" % (prefix, stat_name)
                    metric = (stat_path, (now, stat_val))
                    logging.debug("metric = %s" % str(metric))
                    metric_list.append(metric)
            else:
                logging.debug("Skipping TMM...")

            # Client SSL

            if not no_client_ssl:
                logging.info("Retrieving client SSL statistics...")
                client_ssl_stats = b.System.Statistics.get_client_ssl_statistics()
                logging.debug("client_ssl_stats =\n%s" % pformat(client_ssl_stats))
                statistics = client_ssl_stats['statistics']
                ts = client_ssl_stats['time_stamp']
                now = generate_timestamp(use_remote_ts=remote_ts, remote_ts=ts,
                                         remote_tz=remote_tz)
                for y in statistics:
                    stat_name, stat_val = parse_statistic(statistic=y)
                    stat_path = "%s.client_ssl.%s" % (prefix, stat_name)
                    metric = (stat_path, (now, stat_val))
                    logging.debug("metric = %s" % str(metric))
                    metric_list.append(metric)
            else:
                logging.debug("Skipping client SSL...")

            # Interfaces

            if not no_interface:
                logging.info("Retrieving list of interfaces...")
                interfaces = b.Networking.Interfaces.get_list()
                logging.debug("interfaces = %s" % pformat(interfaces))
                if interfaces:
                    logging.info("Retrieving interface statistics...")
                    int_stats = b.Networking.Interfaces.get_statistics(interfaces)
                    logging.debug("int_stats =\n%s" % pformat(int_stats))
                    statistics = int_stats['statistics']
                    ts = int_stats['time_stamp']
                    now = generate_timestamp(use_remote_ts=remote_ts,
                                             remote_ts=ts, remote_tz=remote_tz)
                    for x in statistics:
                        int_name = x['interface_name'].replace('.', '-')
                        for y in x['statistics']:
                            stat_name, stat_val = parse_statistic(statistic=y)
                            stat_path = "%s.interface.%s.%s" % (prefix, int_name, stat_name)
                            metric = (stat_path, (now, stat_val))
                            logging.debug("metric = %s" % str(metric))
                            metric_list.append(metric)
            else:
                logging.debug("Skipping interfaces...")

            # Trunk

            if not no_trunk:
                logging.info("Retrieving list of trunks...")
                trunks = b.Networking.Trunk.get_list()
                logging.debug("trunks =\n%s" % pformat(trunks))
                if trunks:
                    logging.info("Retrieving trunk statistics...")
                    trunk_stats = b.Networking.Trunk.get_statistics(trunks)
                    logging.debug("trunk_stats =\n%s" % pformat(trunk_stats))
                    statistics = trunk_stats['statistics']
                    ts = trunk_stats['time_stamp']
                    now = generate_timestamp(use_remote_ts=remote_ts,
                                             remote_ts=ts, remote_tz=remote_tz)
                    for x in statistics:
                        trunk_name = x['trunk_name'].replace('.', '-')
                        for y in x['statistics']:
                            stat_name, stat_val = parse_statistic(statistic=y)
                            stat_path = "%s.trunk.%s.%s" % (prefix, trunk_name, stat_name)
                            metric = (stat_path, (now, stat_val))
                            logging.debug("metric = %s" % str(metric))
                            metric_list.append(metric)
            else:
                logging.debug("Skipping trunks...")

            # CPU

            if not no_cpu:
                logging.info("Retrieving CPU statistics...")
                cpu_stats = b.System.SystemInfo.get_all_cpu_usage_extended_information()
                logging.debug("cpu_stats =\n%s" % pformat(cpu_stats))
                statistics = cpu_stats['hosts']
                ts = cpu_stats['time_stamp']
                now = generate_timestamp(use_remote_ts=remote_ts, remote_ts=ts,
                                         remote_tz=remote_tz)
                for x in statistics:
                    host_id = x['host_id'].replace('.', '-')
                    for cpu_num, cpu_stat in enumerate(x['statistics']):
                        for y in cpu_stat:
                            stat_name, stat_val = parse_statistic(statistic=y)
                            stat_path = "%s.cpu.%s.cpu%s.%s" % (prefix, host_id, cpu_num, stat_name)
                            metric = (stat_path, (now, stat_val))
                            logging.debug("metric = %s" % str(metric))
                            metric_list.append(metric)
            else:
                logging.debug("Skipping CPU...")

            # Host

            if not no_host:
                logging.info("Retrieving host statistics...")
                host_stats = b.System.Statistics.get_all_host_statistics()
                logging.debug("host_stats =\n%s" % pformat(host_stats))
                statistics = host_stats['statistics']
                ts = host_stats['time_stamp']
                now = generate_timestamp(use_remote_ts=remote_ts, remote_ts=ts,
                                         remote_tz=remote_tz)
                for x in statistics:
                    host_id = x['host_id'].replace('.', '-')
                    for y in x['statistics']:
                        stat_name, stat_val = parse_statistic(statistic=y)
                        if stat_name.startswith("memory_"):
                            # throw memory stats into dedicated memory section
                            stat_path = "%s.memory.%s.%s" % (prefix, host_id, stat_name)
                        else:
                            # catch-all
                            stat_path = "%s.system.host.%s.%s" % (prefix, host_id, stat_name)
                        metric = (stat_path, (now, stat_val))
                        logging.debug("metric = %s" % str(metric))
                        metric_list.append(metric)
            else:
                logging.debug("Skipping host statistics...")

            # SNAT Pool

            if not no_snat_pool:
                logging.info("Retrieving SNAT Pool statistics...")
                snatpool_stats = b.LocalLB.SNATPool.get_all_statistics()
                logging.debug("snatpool_stats = %s" % pformat(snatpool_stats))
                statistics = snatpool_stats['statistics']
                ts = snatpool_stats['time_stamp']
                now = generate_timestamp(use_remote_ts=remote_ts, remote_ts=ts,
                                         remote_tz=remote_tz)
                for x in statistics:
                    snat_pool = x['snat_pool'].replace(".", '-')
                    for y in x['statistics']:
                        stat_name, stat_val = parse_statistic(statistic=y)
                        stat_path = "%s.snat_pool.%s.%s" % (prefix, snat_pool, stat_name)
                        metric = (stat_path, (now, stat_val))
                        logging.debug("metric = %s" % str(metric))
                        metric_list.append(metric)
            else:
                logging.debug("Skipping SNAT pools...")

            # SNAT Translations

            if not no_snat_translation:
                logging.info("Retrieving SNAT translation statistics...")
                snattrans_stats = b.LocalLB.SNATTranslationAddressV2.get_all_statistics()
                logging.debug("snattrans_stats = %s" % pformat(snattrans_stats))
                statistics = snattrans_stats['statistics']
                ts = snattrans_stats['time_stamp']
                now = generate_timestamp(use_remote_ts=remote_ts, remote_ts=ts,
                                         remote_tz=remote_tz)
                for x in statistics:
                    trans_addr = x['translation_address'].replace(".", '-')
                    for y in x['statistics']:
                        stat_name, stat_val = parse_statistic(statistic=y)
                        stat_path = "%s.snat_translation.%s.%s" % (prefix, trans_addr, stat_name)
                        metric = (stat_path, (now, stat_val))
                        logging.debug("metric = %s" % str(metric))
                        metric_list.append(metric)
            else:
                logging.debug("Skipping SNAT translations...")

            # Virtual server

            if not no_virtual_server:
                logging.info("Retrieving statistics for all virtual servers...")
                virt_stats = b.LocalLB.VirtualServer.get_all_statistics()
                logging.debug("virt_stats =\n%s" % pformat(virt_stats))
                statistics = virt_stats['statistics']
                ts = virt_stats['time_stamp']
                now = generate_timestamp(use_remote_ts=remote_ts, remote_ts=ts,
                                         remote_tz=remote_tz)
                for x in statistics:
                    vs_name = x['virtual_server']['name'].replace('.', '-')
                    for y in x['statistics']:
                        stat_name, stat_val = parse_statistic(statistic=y)
                        stat_path = "%s.vs.%s.%s" % (prefix, vs_name, stat_name)
                        metric = (stat_path, (now, stat_val))
                        logging.debug("metric = %s" % str(metric))
                        metric_list.append(metric)
            else:
                logging.debug("Skipping virtual servers...")

            # Pool

            if not no_pool:
                logging.info("Retrieving statistics for all pools...")
                pool_stats = b.LocalLB.Pool.get_all_statistics()
                logging.debug("pool_stats =\n%s" % pformat(pool_stats))
                statistics = pool_stats['statistics']
                ts = pool_stats['time_stamp']
                now = generate_timestamp(use_remote_ts=remote_ts, remote_ts=ts,
                                         remote_tz=remote_tz)
                for x in statistics:
                    pool_name = x['pool_name'].replace('.', '-')
                    for y in x['statistics']:
                        stat_name, stat_val = parse_statistic(statistic=y)
                        stat_path = "%s.pool.%s.%s" % (prefix, pool_name, stat_name)
                        metric = (stat_path, (now, stat_val))
                        logging.debug("metric = %s" % str(metric))
                        metric_list.append(metric)
                # Reuse previous timestamp (a.k.a. fake it!)
                logging.info("Retrieving pool list...")
                pool_list = b.LocalLB.Pool.get_list()
                logging.debug("pool_list =\n%s" % pformat(pool_list))
                if pool_list:
                    logging.info("Retrieving active member count for all pools...")
                    active_member_count = b.LocalLB.Pool.get_active_member_count(pool_names=pool_list)
                    for pool_name, stat_val in zip(pool_list, active_member_count):
                        stat_path = "%s.pool.%s.active_member_count" % (prefix, pool_name)
                        metric = (stat_path, (now, stat_val))
                        logging.debug("metric = %s" % str(metric))
                        metric_list.append(metric)
                    logging.info("Retrieving member count for all pools...")
                    pool_members = b.LocalLB.Pool.get_member_v2(pool_names=pool_list)
                    pool_member_count = [len(x) for x in pool_members]
                    for pool_name, stat_val in zip(pool_list, pool_member_count):
                        stat_path = "%s.pool.%s.member_count" % (prefix, pool_name)
                        metric = (stat_path, (now, stat_val))
                        logging.debug("metric = %s" % str(metric))
                        metric_list.append(metric)
                else:
                    logging.info("Pool list is empty, skipping member count retrieval.")
            else:
                logging.debug("Skipping pools...")

            # Pool members

            if not no_pool_member:
                logging.info("Retrieving pool list...")
                pool_list = b.LocalLB.Pool.get_list()
                logging.debug("pool_list =\n%s" % pformat(pool_list))
                if pool_list:
                    logging.info("Retrieving pool member statistics for all pools...")
                    pool_member_stats = b.LocalLB.Pool.get_all_member_statistics(pool_names=pool_list)
                    logging.debug("pool_member_stats =\n%s" % pformat(pool_member_stats))
                    for pool_name, x in zip(pool_list, pool_member_stats):
                        statistics = x['statistics']
                        ts = x['time_stamp']
                        now = generate_timestamp(use_remote_ts=remote_ts,
                                                 remote_ts=ts,
                                                 remote_tz=remote_tz)
                        for y in statistics:
                            pool_member_name = y['member']['address'].replace('.', '-')
                            pool_member_port = y['member']['port']
                            logging.debug("y = %s" % y)
                            for z in y['statistics']:
                                stat_name, stat_val = parse_statistic(statistic=z)
                                stat_path = "%s.pool_member.%s.%s.%s.%s" % (prefix, pool_name, pool_member_name, pool_member_port, stat_name)
                                metric = (stat_path, (now, stat_val))
                                logging.debug("metric = %s" % str(metric))
                                metric_list.append(metric)
            else:
                logging.debug("Skipping pool members...")

            if not no_node:
                logging.info("Retrieving node statistics...")
                node_stats = b.LocalLB.NodeAddressV2.get_all_statistics()
                logging.debug("node_stats =\n%s" % pformat(node_stats))
                statistics = node_stats['statistics']
                ts = node_stats['time_stamp']
                now = generate_timestamp(use_remote_ts=remote_ts, remote_ts=ts,
                                         remote_tz=remote_tz)
                for x in statistics:
                    node_name = x['node'].replace('.', '-')
                    for y in x['statistics']:
                        stat_name, stat_val = parse_statistic(statistic=y)
                        stat_path = "%s.node.%s.%s" % (prefix, node_name, stat_name)
                        metric = (stat_path, (now, stat_val))
                        logging.debug("metric = %s" % str(metric))
                        metric_list.append(metric)
            else:
                logging.debug("Skipping node statistics...")

            # iRule

            if not no_irule:
                logging.info("Retrieving statistics for all iRules...")
                irule_stats = b.LocalLB.Rule.get_all_statistics()
                logging.debug("irule_stats =\n%s" % pformat(irule_stats))
                statistics = irule_stats['statistics']
                ts = irule_stats['time_stamp']
                now = generate_timestamp(use_remote_ts=remote_ts, remote_ts=ts,
                                         remote_tz=remote_tz)
                for x in statistics:
                    irule_name = x['rule_name'].replace('.', '-')
                    for y in x['statistics']:
                        stat_name, stat_val = parse_statistic(statistic=y)
                        stat_path = "%s.irule.%s.%s" % (prefix, irule_name, stat_name)
                        metric = (stat_path, (now, stat_val))
                        logging.debug("metric = %s" % str(metric))
                        metric_list.append(metric)
            else:
                logging.debug("Skipping iRules...")

            # HTTP Profile

            if not no_http:
                logging.info("Retrieving HTTP profile statistics...")
                http_stats = b.LocalLB.ProfileHttp.get_all_statistics()
                logging.debug("http_stats = %s\n" % pformat(http_stats))
                statistics = http_stats['statistics']
                ts = http_stats['time_stamp']
                now = generate_timestamp(use_remote_ts=remote_ts, remote_ts=ts,
                                         remote_tz=remote_tz)
                for x in statistics:
                    profile_name = x['profile_name'].replace('.', '-')
                    for y in x['statistics']:
                        stat_name, stat_val = parse_statistic(statistic=y)
                        stat_path = "%s.http.%s.%s" % (prefix, profile_name, stat_name)
                        metric = (stat_path, (now, stat_val))
                        logging.debug("metric = %s" % str(metric))
                        metric_list.append(metric)
            else:
                logging.debug("Skipping HTTP profile...")

            # OneConnect

            if not no_oneconnect:
                logging.info("Retrieving OneConnect statistics...")
                oneconnect_stats = b.LocalLB.ProfileOneConnect.get_all_statistics()
                logging.debug("oneconnect_stats =\n%s" % pformat(oneconnect_stats))
                statistics = oneconnect_stats['statistics']
                ts = oneconnect_stats['time_stamp']
                now = generate_timestamp(use_remote_ts=remote_ts, remote_ts=ts,
                                         remote_tz=remote_tz)
                for x in statistics:
                    profile_name = x['profile_name'].replace('.', '-')
                    for y in x['statistics']:
                        stat_name, stat_val = parse_statistic(statistic=y)
                        stat_path = "%s.oneconnect.%s.%s" % (prefix, profile_name, stat_name)
                        metric = (stat_path, (now, stat_val))
                        logging.debug("metric = %s" % str(metric))
                        metric_list.append(metric)
            else:
                logging.debug("Skipping OneConnect...")

            # Temperature

            if not no_temperature:
                logging.info("Retrieving temperature statistics...")
                temperature_stats = b.System.SystemInfo.get_temperature_metrics()
                logging.debug("temperature_stats =\n%s" % pformat(temperature_stats))
                temperatures = temperature_stats['temperatures'][0]  # not sure why this is a list, maybe for viprion platform?
                ts = temperature_stats['time_stamp']
                now = generate_timestamp(use_remote_ts=remote_ts, remote_ts=ts,
                                         remote_tz=remote_tz)
                for x in temperature_stats['temperatures']:
                    logging.debug("x = %s" % x)
                    temperature_index = None
                    temperature_value = None
                    for y in x:
                        if y['metric_type'] == 'TEMPERATURE_INDEX':
                            temperature_index = y['value']
                        elif y['metric_type'] == 'TEMPERATURE_VALUE':
                            temperature_value = y['value']
                    stat_path = "%s.temperature.%s.temperature_value" % (prefix, temperature_index)
                    metric = (stat_path, (now, temperature_value))
                    logging.debug("metric = %s" % str(metric))
                    metric_list.append(metric)
            else:
                logging.debug("Skipping temperatures...")

            # Fan

            if not no_fan:
                logging.info("Retrieving fan statistics...")
                fan_stats = b.System.SystemInfo.get_fan_metrics()
                logging.debug("fan_stats =\n%s" % pformat(fan_stats))
                ts = fan_stats['time_stamp']
                now = generate_timestamp(use_remote_ts=remote_ts, remote_ts=ts,
                                         remote_tz=remote_tz)
                for x in fan_stats['fans']:
                    logging.debug("x = %s" % x)
                    fan_index = None
                    fan_state = None
                    fan_speed = None
                    for y in x:
                        if y['metric_type'] == 'FAN_INDEX':
                            fan_index = y['value']
                        elif y['metric_type'] == 'FAN_STATE':
                            fan_state = y['value']
                        elif y['metric_type'] == 'FAN_SPEED':
                            fan_speed = y['value']
                    stat_path = "%s.fan.%s.fan_state" % (prefix, fan_index)
                    metric = (stat_path, (now, fan_state))
                    logging.debug("metric = %s" % str(metric))
                    metric_list.append(metric)
                    stat_path = "%s.fan.%s.fan_speed" % (prefix, fan_index)
                    metric = (stat_path, (now, fan_speed))
                    logging.debug("metric = %s" % str(metric))
                    metric_list.append(metric)
            else:
                logging.debug("Skipping fans...")

            # Device Group

            if not no_device_group:
                color_lookup = {'COLOR_UNKNOWN': 0,
                                'COLOR_GREEN': 1,
                                'COLOR_YELLOW': 2,
                                'COLOR_RED': 3,
                                'COLOR_BLUE': 4,
                                'COLOR_GRAY': 5,
                                'COLOR_BLACK': 6}

                sync_lookup = {'MEMBER_STATE_UNKNOWN': 0,
                               'MEMBER_STATE_SYNCING': 1,
                               'MEMBER_STATE_NEED_MANUAL_SYNC': 2,
                               'MEMBER_STATE_IN_SYNC': 3,
                               'MEMBER_STATE_SYNC_FAILED': 4,
                               'MEMBER_STATE_SYNC_DISCONNECTED': 5,
                               'MEMBER_STATE_STANDALONE': 6,
                               'MEMBER_STATE_AWAITING_INITIAL_SYNC': 7,
                               'MEMBER_STATE_INCOMPATIBLE_VERSION': 8,
                               'MEMBER_STATE_PARTIAL_SYNC': 9}

                logging.info("Retrieving device group list...")
                device_group_list = b.Management.DeviceGroup.get_list()
                logging.debug("device_group_list =\n%s" % pformat(device_group_list))
                if device_group_list:
                    logging.info("Retrieving sync status of device groups...")
                    device_sync_status = b.Management.DeviceGroup.get_sync_status(device_groups=device_group_list)
                    logging.debug("device_sync_status =\n%s" % pformat(device_sync_status))
                    for device_group, sync_status in zip(device_group_list, device_sync_status):
                        if remote_ts and not now:
                            # remote timestamp not available on this metric and
                            # no previous remote timestamp available -- best we
                            # can do is use local timestamp.
                            logging.debug("No remote timestamp for metric nor previous remote timestamp available, using local.")
                            now = generate_timestamp(use_remote_ts=False,
                                                     remote_ts=None,
                                                     remote_tz=remote_tz)
                        elif not remote_ts:
                            now = generate_timestamp(use_remote_ts=False,
                                                     remote_ts=None,
                                                     remote_tz=remote_tz)
                        else:
                            # use previous remote timestamp
                            logging.debug("No remote timestamp for metric, using previous remote timestamp.")
                            logging.debug("Remote timestamp is %s." % now)
                        device_group_name = device_group.replace('.', '-')
                        stat_val = color_lookup[sync_status['color']]
                        stat_path = "%s.device_group.%s.color" % (prefix, device_group_name)
                        metric = (stat_path, (now, stat_val))
                        logging.debug("metric = %s" % str(metric))
                        metric_list.append(metric)
                        stat_val = sync_lookup[sync_status['member_state']]
                        stat_path = "%s.device_group.%s.member_state" % (prefix, device_group_name)
                        metric = (stat_path, (now, stat_val))
                        logging.debug("metric = %s" % str(metric))
                        metric_list.append(metric)
            else:
                logging.debug("Skipping device groups...")

        except (bigsuds.ServerError, bigsuds.ConnectionError,
                bigsuds.ParseError, httplib.BadStatusLine), detail:
            last_detail = detail
            logging.error("A connection error was encountered.")
            logging.error(detail)
            logging.debug(traceback.format_exc())
            if upload_attempts < max_attempts:  # don't sleep on last run
                logging.info("Sleeping %d seconds before retry..." % interval)
                time.sleep(interval)
        else:
            upload_success = True
    if not upload_success:
        logging.critical("Unable to collect metrics after %d attempts." %
                         upload_attempts)
        logging.critical("Last error: %s" % last_detail)
        sys.exit(1)
    logging.info("%d metrics gathered." % len(metric_list))
    return(metric_list)


def write_json_metrics(metric_list, filename):
    """Write JSON encoded metric_list to disk for later replay.
    """
    metric_list_json = json.dumps(metric_list)
    logging.debug("metric_list_json = %s" % pformat(metric_list_json))
    with open(filename, "w") as f:
        f.write(metric_list_json)


def main():
    parser = get_parser()
    args = parser.parse_args()

    LOGGING_LEVELS = {'critical': logging.CRITICAL,
                      'error': logging.ERROR,
                      'warning': logging.WARNING,
                      'info': logging.INFO,
                      'debug': logging.DEBUG}
    loglevel = LOGGING_LEVELS.get(args.loglevel, logging.NOTSET)
    logging.basicConfig(level=loglevel, filename=args.logfile,
                        format='%(asctime)s %(levelname)s: [%(thread)d ' +
                        '%(module)s:%(funcName)s %(lineno)d] %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    logging.getLogger('suds').setLevel(logging.CRITICAL)
    logging.debug("args = %s" % args)

    if args.ts_auth.strip().lower() == "remote":
        remote_ts = True
    else:
        remote_ts = False

    if args.prefix:
        prefix = args.prefix.strip()
    else:
        scrubbed_f5_host = args.f5_host.replace(".", "_")
        logging.debug("scrubbed_f5_host = %s" % scrubbed_f5_host)
        prefix = "bigip.%s" % scrubbed_f5_host
        logging.debug("prefix = %s" % prefix)

    start_timestamp = timestamp_local()
    logging.debug("start_timestamp = %s" % start_timestamp)

    metric_list = gather_f5_metrics(args.f5_host, args.f5_username,
                                    args.f5_password, args.f5_retries,
                                    args.f5_interval, prefix, remote_ts,
                                    args.no_ip, args.no_ipv6, args.no_icmp,
                                    args.no_icmpv6, args.no_tcp, args.no_tmm,
                                    args.no_client_ssl, args.no_interface,
                                    args.no_trunk, args.no_cpu, args.no_host,
                                    args.no_snat_pool,
                                    args.no_snat_translation,
                                    args.no_virtual_server, args.no_pool,
                                    args.no_pool_member, args.no_irule,
                                    args.no_http, args.no_oneconnect,
                                    args.no_temperature, args.no_fan,
                                    args.no_device_group, args.no_node)

    collection_finish_timestamp = timestamp_local()
    logging.debug("collection_finish_timestamp = %s" % collection_finish_timestamp)
    collection_time = collection_finish_timestamp - start_timestamp
    logging.debug("collection_time = %s" % collection_time)

    # create a metric representing how long F5 statistics collection took
    # don't bother to generate a collection_time metric if nothing collected

    if metric_list:
        if remote_ts:
            # grab first metric and borrow its metric timestamp
            now = metric_list[0][1][0]
        else:
            now = start_timestamp
        stat_path = "%s.agent.collection_time" % prefix
        metric = (stat_path, (now, collection_time))
        logging.debug("metric = %s" % str(metric))
        metric_list.append(metric)

    # filter metric list

    if args.exclude:
        for pattern in args.exclude:
            metric_list = [m for m in metric_list if not fnmatchcase(m[0], pattern)]
        logging.debug("metric_list =\n%s" % pformat(metric_list))

    if not args.skip_upload and args.carbon_host:
        upload_attempts = 0
        upload_success = False
        max_attempts = args.carbon_retries + 1
        while not upload_success and (upload_attempts < max_attempts):
            upload_attempts += 1
            logging.info("Uploading metrics (try #%d/%d)..." %
                         (upload_attempts, max_attempts))
            with Carbon(args.carbon_host, args.carbon_port,
                        args.carbon_encoding) as carbon:
                try:
                    carbon.connect()
                    carbon.send(metric_list, args.chunk_size)
                    carbon.close()
                except Exception, detail:
                    logging.error("Unable to upload metrics.")
                    logging.debug(Exception)
                    logging.debug(detail)
                    upload_success = False
                    if upload_attempts < max_attempts:  # don't sleep after last run
                        logging.info("Sleeping %d seconds before retry..." %
                                     args.carbon_interval)
                        time.sleep(args.carbon_interval)
                else:
                    upload_success = True
        if not upload_success:
            logging.error("Unable to upload metrics after %d attempts." %
                          upload_attempts)
            logging.info("Saving collected data to local disk for later " +
                         "replay...")
            date_str = datetime.now().strftime("%Y%m%dT%H%M%S")
            logging.debug("date_str = %s" % date_str)
            write_json_metrics(metric_list, "%s_%s_fail.json" %
                               (prefix, date_str))
    else:
        logging.info("Dry-run or no carbon host provided -- skipping " +
                     "upload step.")

    finish_timestamp = timestamp_local()
    logging.debug("finish_timestamp = %s" % finish_timestamp)
    runtime = finish_timestamp - start_timestamp
    logging.info("Elapsed time in seconds is %d." % runtime)


if __name__ == '__main__':
    main()


# to-do:
#
# - detect connection failures, ie. unable to connect to server
# - put each metric collection in a try expect and return partial
# - reload capabilities should be moved into separate utility

