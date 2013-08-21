#!/usr/bin/python

# Author: Matt Hite
# Email: mhite@hotmail.com
# 8/19/2013

import xmltodict
import time
import socket
import pickle
import struct
import optparse
import logging
import getpass
import sys
import json
from datetime import datetime
from pprint import pformat
from ncclient import manager

VERSION="1.1"


def chunks(l, n):
    """ Yield successive n-sized chunks from l.
    """
    for i in xrange(0, len(l), n):
        yield l[i:i+n]


def send_metrics(carbon_host, carbon_port, metric_list, chunk_size):
    """
    Connects to a Carbon server and sends chunked metrics as
    a pickled data structure.
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


def timestamp_local():
    """Return local epoch timestamp.
    """
    epoch = long(time.time())
    logging.debug("epoch = %s" % epoch)
    return(epoch)


def gather_juniper_metrics(juniper_host, user, password, port, prefix):
    """ Connects to a Juniper via NetConf and pulls statistics.
    """
    metric_list = []

    try:
        logging.info("Connecting to %s and pulling statistics..." % juniper_host)
        j = manager.connect_ssh(juniper_host, username=user, password=password, port=port)
    except Exception, detail:
        logging.debug("detail = %s" % pformat(detail))
        pass

    now = timestamp_local()
    logging.debug("Local timestamp is %s." % now)

    logging.info("Retrieving real-time performance monitoring probe statistics...")
    try:
        response = j.dispatch("get-probe-results")
        logging.debug("response = %s" % pformat(response))
    except Exception, detail:
        logging.debug("detail = %s" % pformat(detail))
        pass

    try:
        response_dict = xmltodict.parse(response.xml)
        logging.debug("response_dict = %s" % pformat(response_dict))
    except Exception, detail:
        logging.debug("detail = %s" % pformat(detail))
        pass

    if "probe-results" in response_dict["rpc-reply"] and response_dict["rpc-reply"]["probe-results"] is not None:
        for x in response_dict["rpc-reply"]["probe-results"]["probe-test-results"]:
            probe_name = x["test-name"]
            logging.debug("probe_name = %s" % probe_name)
            rtt = x["probe-single-results"]["rtt"]
            logging.debug("rtt = %s" % rtt)
            stat_name = 'rtt'
            stat_val = long(rtt)
            stat_path = "%s.probe.%s.%s" % (prefix, probe_name, stat_name)
            metric = (stat_path, (now, stat_val))
            logging.debug("metric = %s" % str(metric))
            metric_list.append(metric)
            egress = x["probe-single-results"]["egress"]
            logging.debug("egress = %s" % egress)
            stat_name = 'egress'
            stat_val = long(egress)
            stat_path = "%s.probe.%s.%s" % (prefix, probe_name, stat_name)
            metric = (stat_path, (now, stat_val))
            logging.debug("metric = %s" % str(metric))
            metric_list.append(metric)
            ingress = x["probe-single-results"]["ingress"]
            logging.debug("ingress = %s" % ingress)
            stat_name = 'ingress'
            stat_val = long(ingress)
            stat_path = "%s.probe.%s.%s" % (prefix, probe_name, stat_name)
            metric = (stat_path, (now, stat_val))
            logging.debug("metric = %s" % str(metric))
            metric_list.append(metric)
            egress_jitter = x["probe-single-results"]["egress-jitter"]
            logging.debug("egress_jitter = %s" % egress_jitter)
            stat_name = 'egress-jitter'
            stat_val = long(egress_jitter)
            stat_path = "%s.probe.%s.%s" % (prefix, probe_name, stat_name)
            metric = (stat_path, (now, stat_val))
            logging.debug("metric = %s" % str(metric))
            metric_list.append(metric)
            ingress_jitter =x["probe-single-results"]["ingress-jitter"]
            logging.debug("ingress_jitter = %s" % ingress_jitter)
            stat_name = 'ingress-jitter'
            stat_val = long(ingress_jitter)
            stat_path = "%s.probe.%s.%s" % (prefix, probe_name, stat_name)
            metric = (stat_path, (now, stat_val))
            logging.debug("metric = %s" % str(metric))
            metric_list.append(metric)
            round_trip_jitter = x["probe-single-results"]["round-trip-jitter"]
            logging.debug("round_trip_jitter = %s" % round_trip_jitter)
            stat_name = 'round-trip-jitter'
            stat_val = long(round_trip_jitter)
            stat_path = "%s.probe.%s.%s" % (prefix, probe_name, stat_name)
            metric = (stat_path, (now, stat_val))
            logging.debug("metric = %s" % str(metric))
            metric_list.append(metric)
            egress_interarrival_jitter = x["probe-single-results"]["egress-interarrival-jitter"]
            logging.debug("egress_interarrival_jitter = %s" % egress_interarrival_jitter)
            stat_name = 'egress-interarrival-jitter'
            stat_val = long(egress_interarrival_jitter)
            stat_path = "%s.probe.%s.%s" % (prefix, probe_name, stat_name)
            metric = (stat_path, (now, stat_val))
            logging.debug("metric = %s" % str(metric))
            metric_list.append(metric)
            ingress_interarrival_jitter = x["probe-single-results"]["ingress-interarrival-jitter"]
            logging.debug("ingress_interarrival_jitter = %s" % ingress_interarrival_jitter)
            stat_name = 'ingress-interarrival-jitter'
            stat_val = long(ingress_interarrival_jitter)
            stat_path = "%s.probe.%s.%s" % (prefix, probe_name, stat_name)
            metric = (stat_path, (now, stat_val))
            logging.debug("metric = %s" % str(metric))
            metric_list.append(metric)
            round_trip_interarrival_jitter = x["probe-single-results"]["round-trip-interarrival-jitter"]
            logging.debug("round_trip_interarrival_jitter = %s" % round_trip_interarrival_jitter)
            stat_name = 'round-trip-interarrival-jitter'
            stat_val = long(round_trip_interarrival_jitter)
            stat_path = "%s.probe.%s.%s" % (prefix, probe_name, stat_name)
            metric = (stat_path, (now, stat_val))
            logging.debug("metric = %s" % str(metric))
            metric_list.append(metric)

    now = timestamp_local()
    logging.debug("Local timestamp is %s." % now)

    logging.info("Retrieving firewall filter statistics...")
    try:
        response = j.dispatch("get-firewall-information")
        logging.debug("response = %s" % pformat(response))
    except Exception, detail:
        logging.debug("detail = %s" % pformat(detail))
        pass

    try:
        response_dict = xmltodict.parse(response.xml)
        logging.debug("response_dict = %s" % pformat(response_dict))
    except Exception, detail:
        logging.debug("detail = %s" % pformat(detail))
        pass

    for x in response_dict["rpc-reply"]["firewall-information"]["filter-information"]:
        logging.debug("filter-name = %s" % x['filter-name'])
        filter_name = x['filter-name'].replace('/', '_').replace('.', '_')
        if 'counter' in x:
            if 'counter-name' in x['counter']:
                logging.debug("counter-name = %s" % x['counter']['counter-name'])
                counter_name = x['counter']['counter-name'].replace('/', '_').replace('.', '_')
                logging.debug("counter-packet-count = %s" % x['counter']['packet-count'])
                stat_name = 'packet-count'
                stat_val = long(x['counter']['packet-count'])
                stat_path = "%s.firewall.filter.%s.counter.%s.%s" % (prefix, filter_name, counter_name, stat_name)
                metric = (stat_path, (now, stat_val))
                logging.debug("metric = %s" % str(metric))
                metric_list.append(metric)
                logging.debug("counter-byte-count = %s" % x['counter']['byte-count'])
                stat_name = 'byte-count'
                stat_val = long(x['counter']['byte-count'])
                stat_path = "%s.firewall.filter.%s.counter.%s.%s" % (prefix, filter_name, counter_name, stat_name)
                metric = (stat_path, (now, stat_val))
                logging.debug("metric = %s" % str(metric))
                metric_list.append(metric)
            else:
                # it's a list
                for y in x['counter']:
                    logging.debug("counter-name = %s" % y['counter-name'])
                    counter_name = y['counter-name'].replace('/', '_').replace('.', '_')
                    logging.debug("counter-packet-count = %s" % y['packet-count'])
                    stat_name = 'packet-count'
                    stat_val = long(y['packet-count'])
                    stat_path = "%s.firewall.filter.%s.counter.%s.%s" % (prefix, filter_name, counter_name, stat_name)
                    metric = (stat_path, (now, stat_val))
                    logging.debug("metric = %s" % str(metric))
                    metric_list.append(metric)
                    logging.debug("counter-byte-count = %s" % y['byte-count'])
                    stat_name = 'byte-count'
                    stat_val = long(y['byte-count'])
                    stat_path = "%s.firewall.filter.%s.counter.%s.%s" % (prefix, filter_name, counter_name, stat_name)
                    metric = (stat_path, (now, stat_val))
                    logging.debug("metric = %s" % str(metric))
                    metric_list.append(metric)

        if 'policer' in x:
            if 'policer-name' in x['policer']:
                logging.debug("policer-name = %s" % x['policer']['policer-name'])
                policer_name = x['policer']['policer-name'].replace('/', '_').replace('.', '_')
                logging.debug("policer-packet-count = %s" % x['policer']['packet-count'])
                stat_name = 'packet-count'
                stat_val = long(x['policer']['packet-count'])
                stat_path = "%s.firewall.filter.%s.policer.%s.%s" % (prefix, filter_name, policer_name, stat_name)
                metric = (stat_path, (now, stat_val))
                logging.debug("metric = %s" % str(metric))
                metric_list.append(metric)
                logging.debug("policer-byte-count = %s" % x['policer']['byte-count'])
                stat_name = 'byte-count'
                stat_val = long(x['policer']['byte-count'])
                stat_path = "%s.firewall.filter.%s.policer.%s.%s" % (prefix, filter_name, policer_name, stat_name)
                metric = (stat_path, (now, stat_val))
                logging.debug("metric = %s" % str(metric))
                metric_list.append(metric)
            else:
                # it's a list
                for y in x['policer']:
                    logging.debug("policer-name = %s" % y['policer-name'])
                    policer_name = y['policer-name'].replace('/', '_').replace('.', '_')
                    logging.debug("policer-packet-count = %s" % y['packet-count'])
                    stat_name = 'packet-count'
                    stat_val = long(y['packet-count'])
                    stat_path = "%s.firewall.filter.%s.policer.%s.%s" % (prefix, filter_name, policer_name, stat_name)
                    metric = (stat_path, (now, stat_val))
                    logging.debug("metric = %s" % str(metric))
                    metric_list.append(metric)
                    logging.debug("policer-byte-count = %s" % y['byte-count'])
                    stat_name = 'byte-count'
                    stat_val = long(y['byte-count'])
                    stat_path = "%s.firewall.filter.%s.policer.%s.%s" % (prefix, filter_name, policer_name, stat_name)
                    metric = (stat_path, (now, stat_val))
                    logging.debug("metric = %s" % str(metric))
                    metric_list.append(metric)

    # interface stats

    now = timestamp_local()
    logging.debug("Local timestamp is %s." % now)

    logging.info("Retrieving interface statistics...")
    try:
        response = j.dispatch("get-interface-information")
        logging.debug("response = %s" % pformat(response))
    except Exception, detail:
        logging.debug("detail = %s" % pformat(detail))
        pass

    try:
        response_dict = xmltodict.parse(response.xml)
        logging.debug("response_dict = %s" % pformat(response_dict))
    except Exception, detail:
        logging.debug("detail = %s" % pformat(detail))
        pass

    for x in response_dict['rpc-reply']['interface-information']['physical-interface']:
        if any([x['name'].startswith(name) for name in ('xe', 'lo', 'ae', 'ge')]) and x['admin-status']['#text'] == 'up' and x['oper-status'] == 'up':
                logging.debug("physical name = %s " % x['name'])
                int_name = x['name'].replace('/', '_').replace('.', '_')
                if 'input-bps' in x['traffic-statistics']:
                    logging.debug("input-bps = %s" % x['traffic-statistics']['input-bps'])
                    stat_name = 'input-bps'
                    stat_val = long(x['traffic-statistics']['input-bps'])
                    stat_path = "%s.interface.%s.%s" % (prefix, int_name, stat_name)
                    metric = (stat_path, (now, stat_val))
                    logging.debug("metric = %s" % str(metric))
                    metric_list.append(metric)
                if 'output-bps' in x['traffic-statistics']:
                    logging.debug("output-bps = %s" % x['traffic-statistics']['output-bps'])
                    stat_name = 'output-bps'
                    stat_val = long(x['traffic-statistics']['output-bps'])
                    stat_path = "%s.interface.%s.%s" % (prefix, int_name, stat_name)
                    metric = (stat_path, (now, stat_val))
                    logging.debug("metric = %s" % str(metric))
                    metric_list.append(metric)
                if 'input-pps' in x['traffic-statistics']:
                    logging.debug("input-pps = %s" % x['traffic-statistics']['input-pps'])
                    stat_name = 'input-pps'
                    stat_val = long(x['traffic-statistics']['input-pps'])
                    stat_path = "%s.interface.%s.%s" % (prefix, int_name, stat_name)
                    metric = (stat_path, (now, stat_val))
                    logging.debug("metric = %s" % str(metric))
                    metric_list.append(metric)
                if 'output-pps' in x['traffic-statistics']:
                    logging.debug("output-pps = %s" % x['traffic-statistics']['output-pps'])
                    stat_name = 'output-pps'
                    stat_val = long(x['traffic-statistics']['output-pps'])
                    stat_path = "%s.interface.%s.%s" % (prefix, int_name, stat_name)
                    metric = (stat_path, (now, stat_val))
                    logging.debug("metric = %s" % str(metric))
                    metric_list.append(metric)
                if 'logical-interface' in x:
                    if 'name' in x['logical-interface']:
                        logging.debug("logical name = %s" % x['logical-interface']['name'])
                        int_name = x['logical-interface']['name'].replace('/', '_').replace('.', '_')
                        if 'traffic-statistics' in x['logical-interface']:
                            logging.debug("logical input-packets = %s" % x['logical-interface']['traffic-statistics']['input-packets'])
                            stat_name = 'input-packets'
                            stat_val = long(x['logical-interface']['traffic-statistics']['input-packets'])
                            stat_path = "%s.interface.%s.%s" % (prefix, int_name, stat_name)
                            metric = (stat_path, (now, stat_val))
                            logging.debug("metric = %s" % str(metric))
                            metric_list.append(metric)
                            logging.debug("logical output-packets = %s" % x['logical-interface']['traffic-statistics']['output-packets'])
                            stat_name = 'output-packets'
                            stat_val = long(x['logical-interface']['traffic-statistics']['output-packets'])
                            stat_path = "%s.interface.%s.%s" % (prefix, int_name, stat_name)
                            metric = (stat_path, (now, stat_val))
                            logging.debug("metric = %s" % str(metric))
                            metric_list.append(metric)
                    else:
                        # it's a list
                        for y in x['logical-interface']:
                            if 'name' in y:
                                int_name = y['name'].replace('/', '_').replace('.', '_')
                                logging.debug("logical name = %s" % y['name'])
                                if 'traffic-statistics' in y:
                                    logging.debug("logical input-packets = %s" % y['traffic-statistics']['input-packets'])
                                    stat_name = 'input-packets'
                                    stat_val = long(y['traffic-statistics']['input-packets'])
                                    stat_path = "%s.interface.%s.%s" % (prefix, int_name, stat_name)
                                    metric = (stat_path, (now, stat_val))
                                    logging.debug("metric = %s" % str(metric))
                                    metric_list.append(metric)
                                    logging.debug("logical output-packets = %s" % y['traffic-statistics']['output-packets'])
                                    stat_name = 'output-packets'
                                    stat_val = long(y['traffic-statistics']['output-packets'])
                                    stat_path = "%s.interface.%s.%s" % (prefix, int_name, stat_name)
                                    metric = (stat_path, (now, stat_val))
                                    logging.debug("metric = %s" % str(metric))
                                    metric_list.append(metric)
                                if ('lag-traffic-statistics' in y) and ('lag-bundle' in y['lag-traffic-statistics']):
                                    # it's a lag
                                    logging.debug("logical input-packets = %s" % y['lag-traffic-statistics']['lag-bundle']['input-packets'])
                                    stat_name = 'input-packets'
                                    stat_val = long(y['lag-traffic-statistics']['lag-bundle']['input-packets'])
                                    stat_path = "%s.interface.%s.%s" % (prefix, int_name, stat_name)
                                    metric = (stat_path, (now, stat_val))
                                    logging.debug("metric = %s" % str(metric))
                                    metric_list.append(metric)
                                    logging.debug("logical output-packets = %s" % y['lag-traffic-statistics']['lag-bundle']['output-packets'])
                                    stat_name = 'output-packets'
                                    stat_val = long(y['lag-traffic-statistics']['lag-bundle']['output-packets'])
                                    stat_path = "%s.interface.%s.%s" % (prefix, int_name, stat_name)
                                    metric = (stat_path, (now, stat_val))
                                    logging.debug("metric = %s" % str(metric))
                                    metric_list.append(metric)
                                    logging.debug("logical input-pps = %s" % y['lag-traffic-statistics']['lag-bundle']['input-pps'])
                                    stat_name = 'input-pps'
                                    stat_val = long(y['lag-traffic-statistics']['lag-bundle']['input-pps'])
                                    stat_path = "%s.interface.%s.%s" % (prefix, int_name, stat_name)
                                    metric = (stat_path, (now, stat_val))
                                    logging.debug("metric = %s" % str(metric))
                                    metric_list.append(metric)
                                    logging.debug("logical output-pps = %s" % y['lag-traffic-statistics']['lag-bundle']['output-pps'])
                                    stat_name = 'output-pps'
                                    stat_val = long(y['lag-traffic-statistics']['lag-bundle']['output-pps'])
                                    stat_path = "%s.interface.%s.%s" % (prefix, int_name, stat_name)
                                    metric = (stat_path, (now, stat_val))
                                    logging.debug("metric = %s" % str(metric))
                                    metric_list.append(metric)
                                    logging.debug("logical input-bytes = %s" % y['lag-traffic-statistics']['lag-bundle']['input-bytes'])
                                    stat_name = 'input-bytes'
                                    stat_val = long(y['lag-traffic-statistics']['lag-bundle']['input-bytes'])
                                    stat_path = "%s.interface.%s.%s" % (prefix, int_name, stat_name)
                                    metric = (stat_path, (now, stat_val))
                                    logging.debug("metric = %s" % str(metric))
                                    metric_list.append(metric)
                                    logging.debug("logical output-bytes = %s" % y['lag-traffic-statistics']['lag-bundle']['output-bytes'])
                                    stat_name = 'output-bytes'
                                    stat_val = long(y['lag-traffic-statistics']['lag-bundle']['output-bytes'])
                                    stat_path = "%s.interface.%s.%s" % (prefix, int_name, stat_name)
                                    metric = (stat_path, (now, stat_val))
                                    logging.debug("metric = %s" % str(metric))
                                    metric_list.append(metric)
                                    logging.debug("logical input-bps = %s" % y['lag-traffic-statistics']['lag-bundle']['input-bps'])
                                    stat_name = 'input-bps'
                                    stat_val = long(y['lag-traffic-statistics']['lag-bundle']['input-bps'])
                                    stat_path = "%s.interface.%s.%s" % (prefix, int_name, stat_name)
                                    metric = (stat_path, (now, stat_val))
                                    logging.debug("metric = %s" % str(metric))
                                    metric_list.append(metric)
                                    logging.debug("logical output-bps = %s" % y['lag-traffic-statistics']['lag-bundle']['output-bps'])
                                    stat_name = 'output-bps'
                                    stat_val = long(y['lag-traffic-statistics']['lag-bundle']['output-bps'])
                                    stat_path = "%s.interface.%s.%s" % (prefix, int_name, stat_name)
                                    metric = (stat_path, (now, stat_val))
                                    logging.debug("metric = %s" % str(metric))
                                    metric_list.append(metric)
    logging.info("There are %d metrics to load." % len(metric_list))
    return(metric_list)


def write_json_metrics(metric_list, filename):
    """ Write JSON encoded metric_list to disk for later replay.
    """
    metric_list_json = json.dumps(metric_list)
    logging.debug("metric_list_json = %s" % pformat(metric_list_json))
    with open(filename, "w") as f:
        f.write(metric_list_json)


def main():
    p = optparse.OptionParser(version=VERSION,
                              usage="usage: %prog [options] juniper_host carbon_host",
                              description="Juniper graphite agent")
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
    p.add_option('-r', '--carbon-retries', help="Number of carbon server delivery attempts [%default]", type="int", dest="carbon_retries", default=2)
    p.add_option('-i', '--carbon-interval', help="Interval between carbon delivery attempts [%default]", type="int", dest="carbon_interval", default=30)
    p.add_option('-c', '--chunk-size', help='Carbon chunk size [%default]', type="int", dest='chunk_size', default=500)
    p.add_option('-n', '--netconf-port', help="NetConf port [%default]", type="int", dest="netconf_port", default=8020)
    p.add_option('--prefix', help="Metric name prefix [juniper.juniper_host]", dest="prefix")

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
    carbon_retries = options.carbon_retries
    logging.debug("carbon_retries = %s" % carbon_retries)
    carbon_interval = options.carbon_interval
    logging.debug("carbon_interval = %s" % carbon_interval)
    netconf_port = options.netconf_port
    logging.debug("netconf_port = %s" % netconf_port)

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

    juniper_host = arguments[0]
    logging.debug("juniper_host = %s" % juniper_host)

    if options.prefix:
        prefix = options.prefix.strip()
    else:
        scrubbed_juniper_host = juniper_host.replace(".", "_")
        logging.debug("scrubbed_juniper_host = %s" % scrubbed_juniper_host)
        prefix = "juniper.%s" % scrubbed_juniper_host
        logging.debug("prefix = %s" % prefix)

    carbon_host = arguments[1]
    logging.debug("carbon_host = %s" % carbon_host)

    start_timestamp = timestamp_local()
    logging.debug("start_timestamp = %s" % start_timestamp)

    metric_list = gather_juniper_metrics(juniper_host, user, password, netconf_port, prefix)

    if not skip_upload:
        upload_attempts = 0
        upload_success = False
        max_attempts = carbon_retries + 1
        while not upload_success and (upload_attempts < max_attempts):
            upload_attempts += 1
            logging.info("Uploading metrics (try #%d/%d)..." % (upload_attempts, max_attempts))
            try:
                send_metrics(carbon_host, carbon_port, metric_list, chunk_size)
            except Exception, detail:
                logging.error("Unable to upload metrics.")
                logging.debug(Exception)
                logging.debug(detail)
                upload_success = False
                if upload_attempts < max_attempts:  # don't sleep on last run
                    logging.info("Sleeping %d seconds before retry..." % carbon_interval)
                    time.sleep(carbon_interval)
            else:
                upload_success = True
        if not upload_success:
            logging.error("Unable to upload metrics after %d attempts." % upload_attempts)
            logging.info("Saving collected data to local disk for later replay...")
            date_str = datetime.now().strftime("%Y%m%dT%H%M%S")
            logging.debug("date_str = %s" % date_str)
            write_json_metrics(metric_list, "%s_%s_fail.json" % (prefix, date_str))
    else:
        logging.info("Skipping upload step.")

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


# - handle: 2013-03-05 21:32:11 DEBUG: detail = SSHUnknownHostError('Unknown host key [5c:54:eb:d7:b0:53:d6:7a:3b:2c:ca:19:17:b1:7c:2c] for [172.20.0.3]',)

