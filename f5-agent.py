#!/usr/bin/env python

# Author: Matt Hite
# Email: mhite@hotmail.com
# 12/10/2012

import bigsuds
import time
import socket
import pickle
import struct
import optparse
import logging
import getpass
from datetime import tzinfo, timedelta, datetime
from pprint import pformat

VERSION="1.23"

# list of pool statistics to monitor

POOL_STATISTICS = ['current_sessions',
                   'server_side_bytes_in',
                   'server_side_bytes_out',
                   'server_side_current_connections',
                   'server_side_packets_in',
                   'server_side_packets_out',
                   'server_side_total_connections',
                   'total_requests']

# list of virtual server statistics to monitor

VS_STATISTICS = ['client_side_bytes_in',
                 'client_side_bytes_out',
                 'client_side_current_connections',
                 'client_side_packets_in',
                 'client_side_packets_out',
                 'client_side_total_connections',
                 'maximum_connection_duration',
                 'mean_connection_duration',
                 'minimum_connection_duration',
                 'no_node_errors',
                 'total_requests',
                 'virtual_server_five_min_avg_cpu_usage',
                 'virtual_server_five_sec_avg_cpu_usage',
                 'virtual_server_one_min_avg_cpu_usage',
                 'virtual_server_total_cpu_cycles']

# list of interfaces to monitor

INTERFACES = ['3-1', '3-2', 'mgmt']

# SSL

CLIENT_SSL_STATISTICS = ['ssl_five_min_avg_tot_conns',
                         'ssl_five_sec_avg_tot_conns',
                         'ssl_one_min_avg_tot_conns',
                         'ssl_common_total_native_connections',
                         'ssl_common_total_compatible_mode_connections']

# Host

HOST_STATISTICS = ['memory_total_bytes',
                   'memory_used_bytes']


class TZFixedOffset(tzinfo):
    """Fixed offset in minutes east from UTC."""

    def __init__(self, offset, name):
        self.__offset = timedelta(minutes = offset)
        self.__name = name

    def utcoffset(self, dt):
        return self.__offset

    def tzname(self, dt):
        return self.__name

    def dst(self, dt):
        return timedelta(0)


def convert_to_64_bit(high, low):
    """ Converts two 32 bit signed integers to a 64-bit unsigned integer.
    """
    if high < 0:
        high = high + (1 << 32)
    if low < 0:
        low = low + (1 << 32)
    return long((high << 32) | low)


def chunks(l, n):
    """ Yield successive n-sized chunks from l.
    """
    for i in xrange(0, len(l), n):
        yield l[i:i+n]


def timestamp_local():
    """Return local epoch timestamp.
    """
    epoch = int(time.time())
    logging.debug("epoch = %s" % epoch)
    return(epoch)


def convert_to_epoch(year, month, day, hour, minute, second, tz):
    """Converts date/time components to an epoch timestamp.
    """
    dt = datetime(year, month, day, hour, minute, second, tzinfo=tz)
    logging.debug("dt = %s" % dt)
    td = dt - datetime(1970, 1, 1, tzinfo=TZFixedOffset(0, "UTC"))
    logging.debug("td = %s" % td)
    epoch = td.seconds + td.days * 24 * 3600
    logging.debug("epoch = %s" % epoch)
    return(epoch)


def gather_f5_metrics(ltm_host, user, password, prefix, remote_ts):
    """ Connects to an F5 via iControl and pulls statistics.
    """
    metric_list = []
    logging.info("Connecting to BIG-IP and pulling statistics...")
    b = bigsuds.BIGIP(hostname=ltm_host, username=user, password=password)
    logging.info("Requesting session...")
    b = b.with_session_id()
    logging.info("Retrieving time zone information...")
    time_zone = b.System.SystemInfo.get_time_zone()
    logging.debug("time_zone = %s" % pformat(time_zone))
    tz = TZFixedOffset(offset=(time_zone['gmt_offset'] * 60), name=time_zone['time_zone'])
    logging.info("Remote time zone is \"%s\"." % time_zone['time_zone'])
    logging.info("Setting recursive query state to enabled...")
    b.System.Session.set_recursive_query_state(state='STATE_ENABLED')
    logging.info("Switching active folder to root...")
    b.System.Session.set_active_folder(folder="/")

    # IP

    logging.info("Retrieving global IP statistics...")
    ip_stats = b.System.Statistics.get_ip_statistics()
    logging.debug("ip_stats =\n%s" % pformat(ip_stats))
    statistics = ip_stats['statistics']
    ts = ip_stats['time_stamp']
    if remote_ts:
        logging.info("Calculating epoch time from remote timestamp...")
        now = convert_to_epoch(ts['year'], ts['month'], ts['day'],
                               ts['hour'], ts['minute'], ts['second'], tz)
        logging.debug("Remote timestamp is %s." % now)
    else:
        now = timestamp_local()
        logging.debug("Local timestamp is %s." % now)
    for y in statistics:
        stat_name = y['type'].split("STATISTIC_")[-1].lower()
        high = y['value']['high']
        low = y['value']['low']
        stat_val = convert_to_64_bit(high, low)
        stat_path = "%s.protocol.ip.%s" % (prefix, stat_name)
        metric = (stat_path, (now, stat_val))
        logging.debug("metric = %s" % str(metric))
        metric_list.append(metric)

    # IPv6

    logging.info("Retrieving global IPv6 statistics...")
    ipv6_stats = b.System.Statistics.get_ipv6_statistics()
    logging.debug("ipv6_stats =\n%s" % pformat(ipv6_stats))
    statistics = ipv6_stats['statistics']
    ts = ipv6_stats['time_stamp']
    if remote_ts:
        logging.info("Calculating epoch time from remote timestamp...")
        now = convert_to_epoch(ts['year'], ts['month'], ts['day'],
                               ts['hour'], ts['minute'], ts['second'], tz)
        logging.debug("Remote timestamp is %s." % now)
    else:
        now = timestamp_local()
        logging.debug("Local timestamp is %s." % now)
    for y in statistics:
        stat_name = y['type'].split("STATISTIC_")[-1].lower()
        high = y['value']['high']
        low = y['value']['low']
        stat_val = convert_to_64_bit(high, low)
        stat_path = "%s.protocol.ipv6.%s" % (prefix, stat_name)
        metric = (stat_path, (now, stat_val))
        logging.debug("metric = %s" % str(metric))
        metric_list.append(metric)

    # ICMP

    logging.info("Retrieving global ICMP statistics...")
    icmp_stats = b.System.Statistics.get_icmp_statistics()
    logging.debug("icmp_stats =\n%s" % pformat(icmp_stats))
    statistics = icmp_stats['statistics']
    ts = icmp_stats['time_stamp']
    if remote_ts:
        logging.info("Calculating epoch time from remote timestamp...")
        now = convert_to_epoch(ts['year'], ts['month'], ts['day'],
                               ts['hour'], ts['minute'], ts['second'], tz)
        logging.debug("Remote timestamp is %s." % now)
    else:
        now = timestamp_local()
        logging.debug("Local timestamp is %s." % now)
    for y in statistics:
        stat_name = y['type'].split("STATISTIC_")[-1].lower()
        high = y['value']['high']
        low = y['value']['low']
        stat_val = convert_to_64_bit(high, low)
        stat_path = "%s.protocol.icmp.%s" % (prefix, stat_name)
        metric = (stat_path, (now, stat_val))
        logging.debug("metric = %s" % str(metric))
        metric_list.append(metric)

    # ICMPv6

    logging.info("Retrieving global ICMPv6 statistics...")
    icmpv6_stats = b.System.Statistics.get_icmpv6_statistics()
    logging.debug("icmpv6_stats =\n%s" % pformat(icmpv6_stats))
    statistics = icmpv6_stats['statistics']
    ts = icmpv6_stats['time_stamp']
    if remote_ts:
        logging.info("Calculating epoch time from remote timestamp...")
        now = convert_to_epoch(ts['year'], ts['month'], ts['day'],
                               ts['hour'], ts['minute'], ts['second'], tz)
        logging.debug("Remote timestamp is %s." % now)
    else:
        now = timestamp_local()
        logging.debug("Local timestamp is %s." % now)
    for y in statistics:
        stat_name = y['type'].split("STATISTIC_")[-1].lower()
        high = y['value']['high']
        low = y['value']['low']
        stat_val = convert_to_64_bit(high, low)
        stat_path = "%s.protocol.icmpv6.%s" % (prefix, stat_name)
        metric = (stat_path, (now, stat_val))
        logging.debug("metric = %s" % str(metric))
        metric_list.append(metric)

    # TCP

    logging.info("Retrieving TCP statistics...")
    tcp_stats = b.System.Statistics.get_tcp_statistics()
    logging.debug("tcp_stats =\n%s" % pformat(tcp_stats))
    statistics = tcp_stats['statistics']
    ts = tcp_stats['time_stamp']
    if remote_ts:
        logging.info("Calculating epoch time from remote timestamp...")
        now = convert_to_epoch(ts['year'], ts['month'], ts['day'],
                               ts['hour'], ts['minute'], ts['second'], tz)
        logging.debug("Remote timestamp is %s." % now)
    else:
        now = timestamp_local()
        logging.debug("Local timestamp is %s." % now)
    for y in statistics:
        stat_name = y['type'].split("STATISTIC_")[-1].lower()
        high = y['value']['high']
        low = y['value']['low']
        stat_val = convert_to_64_bit(high, low)
        stat_path = "%s.protocol.tcp.%s" % (prefix, stat_name)
        metric = (stat_path, (now, stat_val))
        logging.debug("metric = %s" % str(metric))
        metric_list.append(metric)

    # Global TMM

    logging.info("Retrieving global TMM statistics...")
    global_tmm_stats = b.System.Statistics.get_global_tmm_statistics()
    logging.debug("global_tmm_stats =\n%s" % pformat(global_tmm_stats))
    statistics = global_tmm_stats['statistics']
    ts = global_tmm_stats['time_stamp']
    if remote_ts:
        logging.info("Calculating epoch time from remote timestamp...")
        now = convert_to_epoch(ts['year'], ts['month'], ts['day'],
                               ts['hour'], ts['minute'], ts['second'], tz)
        logging.debug("Remote timestamp is %s." % now)
    else:
        now = timestamp_local()
        logging.debug("Local timestamp is %s." % now)
    for y in statistics:
        stat_name = y['type'].split("STATISTIC_")[-1].lower()
        high = y['value']['high']
        low = y['value']['low']
        stat_val = convert_to_64_bit(high, low)
        stat_path = "%s.tmm.global.%s" % (prefix, stat_name)
        metric = (stat_path, (now, stat_val))
        logging.debug("metric = %s" % str(metric))
        metric_list.append(metric)

    # Client SSL

    logging.info("Retrieving client SSL statistics...")
    client_ssl_stats = b.System.Statistics.get_client_ssl_statistics()
    logging.debug("client_ssl_stats =\n%s" % pformat(client_ssl_stats))
    statistics = client_ssl_stats['statistics']
    ts = client_ssl_stats['time_stamp']
    if remote_ts:
        logging.info("Calculating epoch time from remote timestamp...")
        now = convert_to_epoch(ts['year'], ts['month'], ts['day'],
                               ts['hour'], ts['minute'], ts['second'], tz)
        logging.debug("Remote timestamp is %s." % now)
    else:
        now = timestamp_local()
        logging.debug("Local timestamp is %s." % now)
    for y in statistics:
        stat_name = y['type'].split("STATISTIC_")[-1].lower()
        if stat_name in CLIENT_SSL_STATISTICS:
            high = y['value']['high']
            low = y['value']['low']
            stat_val = convert_to_64_bit(high, low)
            stat_path = "%s.client_ssl.%s" % (prefix, stat_name)
            metric = (stat_path, (now, stat_val))
            logging.debug("metric = %s" % str(metric))
            metric_list.append(metric)

    # Interfaces

    logging.info("Retrieving list of interfaces...")
    interfaces = b.Networking.Interfaces.get_list()
    logging.debug("interfaces =\n%s" % pformat(interfaces))
    logging.info("Retrieving interface statistics...")
    int_stats = b.Networking.Interfaces.get_statistics(interfaces)
    logging.debug("int_stats =\n%s" % pformat(int_stats))
    statistics = int_stats['statistics']
    ts = int_stats['time_stamp']
    if remote_ts:
        logging.info("Calculating epoch time from remote timestamp...")
        now = convert_to_epoch(ts['year'], ts['month'], ts['day'],
                               ts['hour'], ts['minute'], ts['second'], tz)
        logging.debug("Remote timestamp is %s." % now)
    else:
        now = timestamp_local()
        logging.debug("Local timestamp is %s." % now)
    for x in statistics:
        int_name = x['interface_name'].replace('.', '-')
        if int_name in INTERFACES:
            for y in x['statistics']:
                stat_name = y['type'].split("STATISTIC_")[-1].lower()
                high = y['value']['high']
                low = y['value']['low']
                stat_val = convert_to_64_bit(high, low)
                stat_path = "%s.interface.%s.%s" % (prefix, int_name, stat_name)
                metric = (stat_path, (now, stat_val))
                logging.debug("metric = %s" % str(metric))
                metric_list.append(metric)

    # Trunk

    logging.info("Retrieving list of trunks...")
    trunks = b.Networking.Trunk.get_list()
    logging.debug("trunks =\n%s" % pformat(trunks))
    logging.info("Retrieving trunk statistics...")
    trunk_stats = b.Networking.Trunk.get_statistics(trunks)
    logging.debug("trunk_stats =\n%s" % pformat(trunk_stats))
    statistics = trunk_stats['statistics']
    ts = trunk_stats['time_stamp']
    if remote_ts:
        logging.info("Calculating epoch time from remote timestamp...")
        now = convert_to_epoch(ts['year'], ts['month'], ts['day'],
                               ts['hour'], ts['minute'], ts['second'], tz)
        logging.debug("Remote timestamp is %s." % now)
    else:
        now = timestamp_local()
        logging.debug("Local timestamp is %s." % now)
    for x in statistics:
        trunk_name = x['trunk_name'].replace('.', '-')
        for y in x['statistics']:
            stat_name = y['type'].split("STATISTIC_")[-1].lower()
            high = y['value']['high']
            low = y['value']['low']
            stat_val = convert_to_64_bit(high, low)
            stat_path = "%s.trunk.%s.%s" % (prefix, trunk_name, stat_name)
            metric = (stat_path, (now, stat_val))
            logging.debug("metric = %s" % str(metric))
            metric_list.append(metric)

    # CPU

    logging.info("Retrieving CPU statistics...")
    cpu_stats = b.System.SystemInfo.get_all_cpu_usage_extended_information()
    logging.debug("cpu_stats =\n%s" % pformat(cpu_stats))
    statistics = cpu_stats['hosts']
    ts = cpu_stats['time_stamp']
    if remote_ts:
        logging.info("Calculating epoch time from remote timestamp...")
        now = convert_to_epoch(ts['year'], ts['month'], ts['day'],
                               ts['hour'], ts['minute'], ts['second'], tz)
        logging.debug("Remote timestamp is %s." % now)
    else:
        now = timestamp_local()
        logging.debug("Local timestamp is %s." % now)
    for x in statistics:
        host_id = x['host_id'].replace('.', '-')
        for cpu_num, cpu_stat in enumerate(x['statistics']):
            for y in cpu_stat:
                stat_name = y['type'].split("STATISTIC_")[-1].lower()
                high = y['value']['high']
                low = y['value']['low']
                stat_val = convert_to_64_bit(high, low)
                stat_path = "%s.cpu.%s.cpu%s.%s" % (prefix, host_id, cpu_num, stat_name)
                metric = (stat_path, (now, stat_val))
                logging.debug("metric = %s" % str(metric))
                metric_list.append(metric)

    # Host

    logging.info("Retrieving host statistics...")
    host_stats = b.System.Statistics.get_all_host_statistics()
    logging.debug("host_stats =\n%s" % pformat(host_stats))
    statistics = host_stats['statistics']
    ts = host_stats['time_stamp']
    if remote_ts:
        logging.info("Calculating epoch time from remote timestamp...")
        now = convert_to_epoch(ts['year'], ts['month'], ts['day'],
                               ts['hour'], ts['minute'], ts['second'], tz)
        logging.debug("Remote timestamp is %s." % now)
    else:
        now = timestamp_local()
        logging.debug("Local timestamp is %s." % now)
    for x in statistics:
        host_id = x['host_id'].replace('.', '-')
        for y in x['statistics']:
            stat_name = y['type'].split("STATISTIC_")[-1].lower()
            if stat_name in HOST_STATISTICS:
                high = y['value']['high']
                low = y['value']['low']
                stat_val = convert_to_64_bit(high, low)
                if stat_name.startswith("memory_"):
                    # throw memory stats into dedicated memory section
                    stat_path = "%s.memory.%s.%s" % (prefix, host_id, stat_name)
                else:
                    # catch-all
                    stat_path = "%s.system.host.%s.%s" % (prefix, host_id, stat_name)
                metric = (stat_path, (now, stat_val))
                logging.debug("metric = %s" % str(metric))
                metric_list.append(metric)

    # SNAT Pool

    logging.info("Retrieving SNAT Pool statistics...")
    snatpool_stats = b.LocalLB.SNATPool.get_all_statistics()
    logging.debug("snatpool_stats = %s" % pformat(snatpool_stats))
    statistics = snatpool_stats['statistics']
    ts = snatpool_stats['time_stamp']
    if remote_ts:
        logging.info("Calculating epoch time from remote timestamp...")
        now = convert_to_epoch(ts['year'], ts['month'], ts['day'],
                               ts['hour'], ts['minute'], ts['second'], tz)
        logging.debug("Remote timestamp is %s." % now)
    else:
        now = timestamp_local()
        logging.debug("Local timestamp is %s." % now)
    for x in statistics:
        snat_pool = x['snat_pool'].replace(".", '-')
        for y in x['statistics']:
            stat_name = y['type'].split("STATISTIC_")[-1].lower()
            high = y['value']['high']
            low = y['value']['low']
            stat_val = convert_to_64_bit(high, low)
            stat_path = "%s.snat_pool.%s.%s" % (prefix, snat_pool, stat_name)
            metric = (stat_path, (now, stat_val))
            logging.debug("metric = %s" % str(metric))
            metric_list.append(metric)

    # SNAT Translations

    logging.info("Retrieving SNAT translation statistics...")
    snattrans_stats = b.LocalLB.SNATTranslationAddressV2.get_all_statistics()
    logging.debug("snattrans_stats = %s" % pformat(snattrans_stats))
    statistics = snattrans_stats['statistics']
    ts = snattrans_stats['time_stamp']
    if remote_ts:
        logging.info("Calculating epoch time from remote timestamp...")
        now = convert_to_epoch(ts['year'], ts['month'], ts['day'],
                               ts['hour'], ts['minute'], ts['second'], tz)
        logging.debug("Remote timestamp is %s." % now)
    else:
        now = timestamp_local()
        logging.debug("Local timestamp is %s." % now)
    for x in statistics:
        trans_addr = x['translation_address'].replace(".", '-')
        for y in x['statistics']:
            stat_name = y['type'].split("STATISTIC_")[-1].lower()
            high = y['value']['high']
            low = y['value']['low']
            stat_val = convert_to_64_bit(high, low)
            stat_path = "%s.snat_translation.%s.%s" % (prefix, trans_addr, stat_name)
            metric = (stat_path, (now, stat_val))
            logging.debug("metric = %s" % str(metric))
            metric_list.append(metric)

    # Virtual server

    logging.info("Retrieving statistics for all virtual servers...")
    virt_stats = b.LocalLB.VirtualServer.get_all_statistics()
    logging.debug("virt_stats =\n%s" % pformat(virt_stats))
    statistics = virt_stats['statistics']
    ts = virt_stats['time_stamp']
    if remote_ts:
        logging.info("Calculating epoch time from remote timestamp...")
        now = convert_to_epoch(ts['year'], ts['month'], ts['day'],
                               ts['hour'], ts['minute'], ts['second'], tz)
        logging.debug("Remote timestamp is %s." % now)
    else:
        now = timestamp_local()
        logging.debug("Local timestamp is %s." % now)
    for x in statistics:
        vs_name = x['virtual_server']['name'].replace('.', '-')
        for y in x['statistics']:
            stat_name = y['type'].split("STATISTIC_")[-1].lower()
            if stat_name in VS_STATISTICS:
                high = y['value']['high']
                low = y['value']['low']
                stat_val = convert_to_64_bit(high, low)
                stat_path = "%s.vs.%s.%s" % (prefix, vs_name, stat_name)
                metric = (stat_path, (now, stat_val))
                logging.debug("metric = %s" % str(metric))
                metric_list.append(metric)

    # Pool

    logging.info("Retrieving statistics for all pools...")
    pool_stats = b.LocalLB.Pool.get_all_statistics()
    logging.debug("pool_stats =\n%s" % pformat(pool_stats))
    statistics = pool_stats['statistics']
    ts = pool_stats['time_stamp']
    if remote_ts:
        logging.info("Calculating epoch time from remote timestamp...")
        now = convert_to_epoch(ts['year'], ts['month'], ts['day'],
                               ts['hour'], ts['minute'], ts['second'], tz)
        logging.debug("Remote timestamp is %s." % now)
    else:
        now = timestamp_local()
        logging.debug("Local timestamp is %s." % now)
    for x in statistics:
        pool_name = x['pool_name'].replace('.', '-')
        for y in x['statistics']:
            stat_name = y['type'].split("STATISTIC_")[-1].lower()
            if stat_name in POOL_STATISTICS:
                high = y['value']['high']
                low = y['value']['low']
                stat_val = convert_to_64_bit(high, low)
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
    else:
        logging.info("Pool list is empty, skipping active member count retrieval.")

    logging.info("There are %d metrics to load." % len(metric_list))
    return(metric_list)


def send_metrics(carbon_host, carbon_port, metric_list, chunk_size):
    """ Connects to a Carbon server and sends metrics.
    """
    # Break metric list into chunked list

    logging.info("Chunking metrics into chunks of %d..." % chunk_size)
    chunked_metrics = chunks(metric_list, chunk_size)

    # Transmit data to carbon server

    logging.info("Connecting to graphite...")
    sock = socket.socket()
    sock.connect((carbon_host, carbon_port))
    for n, x in enumerate(chunked_metrics):
        logging.info("Pickling chunk %d..." % n)
        payload = pickle.dumps(x)
        header = struct.pack("!L", len(payload))
        message = header + payload
        logging.info("Message size is %d." % len(message))
        logging.info("Sending data...")
        sock.sendall(message)
    logging.info("Closing socket...")
    sock.close()


def main():
    p = optparse.OptionParser(version=VERSION,
                              usage="usage: %prog [options] ltm_host carbon_host",
                              description="F5 BIG-IP graphite agent")
    p.add_option('--log-level', '-l',
                 help='Logging level (critical | error | warning | info | debug) [%default]',
                 choices=('critical', 'error', 'warning', 'info', 'debug'),
                 dest='loglevel', default="info")
    p.add_option('--log-filename', '-o', help='Logging output filename',
                 dest='logfile')
    p.add_option('-s', '--skip-upload', action="store_true", dest="skip_upload",
                 default=False, help="Skip metric upload step [%default]")
    p.add_option('-u', '--user', help='Username and password for iControl authentication', dest='user')
    p.add_option('-p', '--port', help="Carbon port [%default]", type="int", dest='carbon_port', default=2004)
    p.add_option('-c', '--chunk-size', help='Carbon chunk size [%default]', type="int", dest='chunk_size', default=500)
    p.add_option('-t', '--timestamp', help='Timestamp authority (local | remote) [%default]', type="choice", dest="ts_auth", choices=['local', 'remote'], default="remote")
    p.add_option('--prefix', help="Metric name prefix [bigip.ltm_host]", dest="prefix")

    options, arguments = p.parse_args()

    # right number of arguments?
    if len(arguments) != 2:
        p.error("wrong number of arguments: ltm_host and carbon_host required")

    LOGGING_LEVELS = {'critical': logging.CRITICAL,
                      'error': logging.ERROR,
                      'warning': logging.WARNING,
                      'info': logging.INFO,
                      'debug': logging.DEBUG}
    loglevel = LOGGING_LEVELS.get(options.loglevel, logging.NOTSET)
    logging.basicConfig(level=loglevel, filename=options.logfile,
                        format='%(asctime)s %(levelname)s: %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    logging.getLogger('suds').setLevel(logging.CRITICAL)

    skip_upload = options.skip_upload
    logging.debug("skip_upload = %s" % skip_upload)
    chunk_size = options.chunk_size
    logging.debug("chunk_size = %s" % chunk_size)
    carbon_port = options.carbon_port
    logging.debug("carbon_port = %s" % carbon_port)
    ts_auth = options.ts_auth.strip().lower()
    if ts_auth == "remote":
        remote_ts = True
    else:
        remote_ts = False
    logging.debug("timestamp_auth = %s" % ts_auth)
    logging.debug("remote_ts = %s" % remote_ts)

    if (not options.user) or (len(options.user) < 1):
        # empty or non-existent --user option
        # need to gather user and password
        user = raw_input("Enter username:")
        password = getpass.getpass("Enter password for user '%s':" % user)
    elif ":" in options.user:
        # --user option present with user and password
        user, password = options.user.split(':', 1)
    else:
        # --user option present with no password
        user = options.user
        password = getpass.getpass("Enter password for user '%s':" % user)

    logging.debug("user = %s" % user)
    logging.debug("password = %s" % password)

    ltm_host = arguments[0]
    logging.debug("ltm_host = %s" % ltm_host)

    if options.prefix:
        prefix = options.prefix.strip()
    else:
        scrubbed_ltm_host = ltm_host.replace(".", "_")
        logging.debug("scrubbed_ltm_host = %s" % scrubbed_ltm_host)
        prefix = "bigip.%s" % scrubbed_ltm_host
        logging.debug("prefix = %s" % prefix)

    carbon_host = arguments[1]
    logging.debug("carbon_host = %s" % carbon_host)

    metric_list = gather_f5_metrics(ltm_host, user, password, prefix, remote_ts)
    if not skip_upload:
        logging.info("Uploading metrics...")
        send_metrics(carbon_host, carbon_port, metric_list, chunk_size)
    else:
        logging.info("Skipping upload step.")


if __name__ == '__main__':
    main()


# to-do:
#
# - detect connection failures, ie. unable to connect to server
# - put each metric collection in a try expect and return partial

