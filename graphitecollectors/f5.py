#!/usr/bin/python

# Author: Matt Hite
# Email: mhite@hotmail.com

import argparse
import logging
import sys
import traceback
from carbonita import Carbon
from datetime import datetime
from fnmatch import fnmatchcase
from .icontrol import get_bigip_api, get_bigip_metrics
from pprint import pformat
from time import sleep
from .util import timestamp_local, write_json_metrics

__VERSION__ = '1.9.4'


def get_parser():
    """Generates an argparse parser.

    Returns:
        An instantiated argparse parser object.
    """
    parser = argparse.ArgumentParser(description='F5 BIG-IP graphite agent',
                                     fromfile_prefix_chars='@')
    parser.add_argument('--version', '-v', action='version',
                        version=__VERSION__)
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
    icontrol_group.add_argument('--f5-host', help='F5 host', dest='f5_host',
                                required=True)
    icontrol_group.add_argument('--f5-retries', help='Number of F5 iControl ' +
                                'connection retry attempts [%(default)d]',
                                type=int, dest='f5_retries', default=2)
    icontrol_group.add_argument('--f5-interval', help='Interval between F5 ' +
                                'iControl connection retry attempts ' +
                                '[%(default)d]', type=int, dest='f5_interval',
                                default=5)
    carbon_group = parser.add_argument_group('carbon')
    carbon_group.add_argument('--carbon-host', help='Carbon host',
                              dest='carbon_host')
    carbon_group.add_argument('-p', '--carbon-port', '--port',
                              help='Carbon port', type=int,
                              dest='carbon_port')
    carbon_group.add_argument('-e', '--carbon-encoding', '--encoding',
                              help='Carbon encoding [%(default)s]',
                              default='plaintext', dest='carbon_encoding',
                              choices=['plaintext', 'pickle'])
    carbon_group.add_argument('-r', '--carbon-retries',
                              help='Number of carbon server delivery ' +
                                   'attempts [%(default)d]', type=int,
                              dest='carbon_retries', default=2)
    carbon_group.add_argument('-i', '--carbon-interval',
                              help='Interval between carbon delivery ' +
                                   'attempts [%(default)d]', type=int,
                              dest='carbon_interval', default=30)
    carbon_group.add_argument('-c', '--chunk-size',
                              help='Carbon chunk size [%(default)d]',
                              type=int, dest='chunk_size', default=500)
    carbon_group.add_argument('--prefix',
                              help='Metric name prefix [bigip.f5_host]',
                              dest='prefix')
    carbon_group.add_argument('-t', '--timestamp',
                              help='Timestamp authority (local | remote) ' +
                                   '[%(default)s]', dest='ts_auth',
                              choices=['local', 'remote'], default='remote')
    carbon_group.add_argument('-s', '--skip-upload', '-d', '--dry-run',
                              help='Skip metric upload step [%(default)s]',
                              action='store_true', dest='skip_upload',
                              default=False)
    metric_group = parser.add_argument_group('metric')
    metric_group.add_argument('--exclude', action='append', dest='exclude',
                              metavar='PATTERN')
    metric_group.add_argument('--no-ip', action='store_true', dest='no_ip')
    metric_group.add_argument('--no-ipv6', action='store_true', dest='no_ipv6')
    metric_group.add_argument('--no-icmp', action='store_true', dest='no_icmp')
    metric_group.add_argument('--no-icmpv6', action='store_true',
                              dest='no_icmpv6')
    metric_group.add_argument('--no-tcp', action='store_true', dest='no_tcp')
    metric_group.add_argument('--no-tmm', action='store_true', dest='no_tmm')
    metric_group.add_argument('--no-client-ssl', action='store_true',
                              dest='no_client_ssl')
    metric_group.add_argument('--no-interface', action='store_true',
                              dest='no_interface')
    metric_group.add_argument('--no-trunk', action='store_true',
                              dest='no_trunk')
    metric_group.add_argument('--no-cpu', action='store_true',
                              dest='no_cpu')
    metric_group.add_argument('--no-host', action='store_true',
                              dest='no_host')
    metric_group.add_argument('--no-snat-pool', action='store_true',
                              dest='no_snat_pool')
    metric_group.add_argument('--no-snat-translation', action='store_true',
                              dest='no_snat_translation')
    metric_group.add_argument('--no-virtual-server', action='store_true',
                              dest='no_virtual_server')
    metric_group.add_argument('--no-pool', action='store_true', dest='no_pool')
    metric_group.add_argument('--no-pool-member', action='store_true',
                              dest='no_pool_member')
    metric_group.add_argument('--no-irule', action='store_true',
                              dest='no_irule')
    metric_group.add_argument('--no-http', action='store_true',
                              dest='no_http')
    metric_group.add_argument('--no-oneconnect', action='store_true',
                              dest='no_oneconnect')
    metric_group.add_argument('--no-temperature', action='store_true',
                              dest='no_temperature')
    metric_group.add_argument('--no-fan', action='store_true', dest='no_fan')
    metric_group.add_argument('--no-device-group', action='store_true',
                              dest='no_device_group')
    metric_group.add_argument('--no-node', action='store_true', dest='no_node')
    metric_group.add_argument('--no-web-acceleration', action='store_true',
                              dest='no_web_acceleration')
    metric_group.add_argument('--no-tcp-profile', action='store_true',
                              dest='no_tcp_profile')
    return parser


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
    logging.debug('args = %s' % args)

    if args.ts_auth.strip().lower() == 'local':
        local_ts = True
    else:
        local_ts = False

    if args.prefix:
        prefix = args.prefix.strip()
    else:
        scrubbed_f5_host = args.f5_host.replace('.', '_')
        logging.debug('scrubbed_f5_host = %s' % scrubbed_f5_host)
        prefix = 'bigip.%s' % scrubbed_f5_host
        logging.debug('prefix = %s' % prefix)

    start_ts = timestamp_local()
    logging.debug('start_ts = %s' % start_ts)

    # parse args and create a list of categories
    # if it starts with 'no_' and is True, omit it

    categories = [k.replace('no_', '') for k, v in args.__dict__.iteritems()
                  if k.startswith('no_') and not v]
    logging.debug('categories = %s' % categories)

    # get handle to API

    api = get_bigip_api(args.f5_host, args.f5_username, args.f5_password,
                        args.f5_retries + 1, args.f5_interval)

    # exit if we have no API handle

    if not api:
        logging.critical('Unable to connect to F5 API. Exiting...')
        sys.exit(1)

    # gather metrics

    metric_list = get_bigip_metrics(api, categories, prefix, local_ts)

    # filter metric list

    if args.exclude:
        for pattern in args.exclude:
            metric_list = [m for m in metric_list if not fnmatchcase(m[0], pattern)]
        logging.debug('metric_list =\n%s' % pformat(metric_list))

    if metric_list and not args.skip_upload and args.carbon_host:
        upload_attempts = 0
        upload_success = False
        max_attempts = args.carbon_retries + 1
        while not upload_success and (upload_attempts < max_attempts):
            upload_attempts += 1
            logging.info('Uploading metrics (try #%d/%d)...' %
                         (upload_attempts, max_attempts))
            with Carbon(args.carbon_host, args.carbon_port,
                        args.carbon_encoding) as carbon:
                try:
                    carbon.connect()
                    carbon.send(metric_list, args.chunk_size)
                    carbon.close()
                except Exception, detail:
                    logging.error('Unable to upload metrics.')
                    logging.debug(Exception)
                    logging.debug(detail)
                    upload_success = False
                    if upload_attempts < max_attempts:
                        # don't sleep after last run
                        logging.info('Sleeping %d seconds before retry...' %
                                     args.carbon_interval)
                        sleep(args.carbon_interval)
                else:
                    upload_success = True
        if not upload_success:
            logging.error('Unable to upload metrics after %d attempts.' %
                          upload_attempts)
            logging.info('Saving collected data to local disk for later ' +
                         'replay...')
            date_str = datetime.now().strftime('%Y%m%dT%H%M%S')
            logging.debug('date_str = %s' % date_str)
            write_json_metrics(metric_list, '%s_%s_fail.json' %
                               (prefix, date_str))
    else:
        logging.info('Dry-run, no carbon host provided, or no metrics to ' +
                     'deliver -- skipping upload step.')

    finish_ts = timestamp_local()
    logging.debug('finish_ts = %s' % finish_ts)
    runtime = finish_ts - start_ts
    logging.info('Elapsed time in seconds is %d.' % runtime)


if __name__ == '__main__':
    main()

