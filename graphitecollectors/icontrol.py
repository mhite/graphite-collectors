#!/usr/bin/python

# Author: Matt Hite
# Email: mhite@hotmail.com

import bigsuds
import httplib
import logging
import traceback
from datetime import datetime
from pprint import pformat
from time import sleep
from .util import timestamp_local, TZFixedOffset

TZ_UTC = TZFixedOffset(0, 'UTC')

# BIG-IP helpers

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


def ts_epoch(ts):
    """
    Converts BIG-IP API timestamp data structure to epoch timestamp.
    """
    dt = datetime(ts['year'], ts['month'], ts['day'], ts['hour'], ts['minute'],
                  ts['second'], tzinfo=TZ_UTC)
    logging.debug('dt = %s' % dt)
    td = dt - datetime(1970, 1, 1, tzinfo=TZ_UTC)
    logging.debug('td = %s' % td)
    epoch = td.seconds + td.days * 24 * 3600
    logging.debug('epoch = %s' % epoch)
    return epoch


def parse_statistic(statistic):
    stat_name = statistic['type'].split('STATISTIC_')[-1].lower()
    high = statistic['value']['high']
    low = statistic['value']['low']
    stat_val = convert_to_64_bit(high, low)
    return (stat_name, stat_val)


#####
#
# standard metric collection routines
#
#####

def get_ip_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving global IP statistics...')
    result = api.System.Statistics.get_ip_statistics()
    logging.debug('result =\n%s' % pformat(result))
    if not ts:
        ts = ts_epoch(result['time_stamp'])
    for statistic in result['statistics']:
        stat_name, stat_val = parse_statistic(statistic)
        stat_path = '%s.protocol.ip.%s' % (prefix, stat_name)
        metric = (stat_path, (ts, stat_val))
        logging.debug('metric = %s' % str(metric))
        metrics.append(metric)
    return metrics


def get_ipv6_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving global IPv6 statistics...')
    result = api.System.Statistics.get_ipv6_statistics()
    logging.debug('result =\n%s' % pformat(result))
    if not ts:
        ts = ts_epoch(result['time_stamp'])
    for statistic in result['statistics']:
        stat_name, stat_val = parse_statistic(statistic)
        stat_path = '%s.protocol.ipv6.%s' % (prefix, stat_name)
        metric = (stat_path, (ts, stat_val))
        logging.debug('metric = %s' % str(metric))
        metrics.append(metric)
    return metrics


def get_icmp_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving global ICMP statistics...')
    result = api.System.Statistics.get_icmp_statistics()
    logging.debug('result = \n%s' % pformat(result))
    if not ts:
        ts = ts_epoch(result['time_stamp'])
    for statistic in result['statistics']:
        stat_name, stat_val = parse_statistic(statistic)
        stat_path = '%s.protocol.icmp.%s' % (prefix, stat_name)
        metric = (stat_path, (ts, stat_val))
        logging.debug('metric = %s' % str(metric))
        metrics.append(metric)
    return metrics


def get_icmpv6_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving global ICMPv6 statistics...')
    result = api.System.Statistics.get_icmpv6_statistics()
    logging.debug('result = \n%s' % pformat(result))
    if not ts:
        ts = ts_epoch(result['time_stamp'])
    for statistic in result['statistics']:
        stat_name, stat_val = parse_statistic(statistic)
        stat_path = '%s.protocol.icmpv6.%s' % (prefix, stat_name)
        metric = (stat_path, (ts, stat_val))
        logging.debug('metric = %s' % str(metric))
        metrics.append(metric)
    return metrics


def get_tcp_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving TCP statistics...')
    result = api.System.Statistics.get_tcp_statistics()
    logging.debug('result = \n%s' % pformat(result))
    if not ts:
        ts = ts_epoch(result['time_stamp'])
    for statistic in result['statistics']:
        stat_name, stat_val = parse_statistic(statistic)
        stat_path = '%s.protocol.tcp.%s' % (prefix, stat_name)
        metric = (stat_path, (ts, stat_val))
        logging.debug('metric = %s' % str(metric))
        metrics.append(metric)
    return metrics


def get_tmm_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving global TMM statistics...')
    result = api.System.Statistics.get_global_tmm_statistics()
    logging.debug('result = \n%s' % pformat(result))
    if not ts:
        ts = ts_epoch(result['time_stamp'])
    for statistic in result['statistics']:
        stat_name, stat_val = parse_statistic(statistic)
        stat_path = '%s.tmm.global.%s' % (prefix, stat_name)
        metric = (stat_path, (ts, stat_val))
        logging.debug('metric = %s' % str(metric))
        metrics.append(metric)
    return metrics


def get_client_ssl_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving client SSL statistics...')
    result = api.System.Statistics.get_client_ssl_statistics()
    logging.debug('result = \n%s' % pformat(result))
    if not ts:
        ts = ts_epoch(result['time_stamp'])
    for statistic in result['statistics']:
        stat_name, stat_val = parse_statistic(statistic)
        stat_path = '%s.client_ssl.%s' % (prefix, stat_name)
        metric = (stat_path, (ts, stat_val))
        logging.debug('metric = %s' % str(metric))
        metrics.append(metric)
    return metrics

#####
#
# special snowflake handlers
#
#####

def get_cpu_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving CPU statistics...')
    cpu_stats = api.System.SystemInfo.get_all_cpu_usage_extended_information()
    logging.debug('cpu_stats =\n%s' % pformat(cpu_stats))
    statistics = cpu_stats['hosts']
    if not ts:
        ts = ts_epoch(cpu_stats['time_stamp'])
    for x in statistics:
        host_id = x['host_id'].replace('.', '-')
        for cpu_num, cpu_stat in enumerate(x['statistics']):
            for y in cpu_stat:
                stat_name, stat_val = parse_statistic(statistic=y)
                stat_path = '%s.cpu.%s.cpu%s.%s' % (prefix, host_id, cpu_num,
                                                    stat_name)
                metric = (stat_path, (ts, stat_val))
                logging.debug('metric = %s' % str(metric))
                metrics.append(metric)
    return metrics


def get_interface_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving list of interfaces...')
    interfaces = api.Networking.Interfaces.get_list()
    logging.debug('interfaces = %s' % pformat(interfaces))
    if interfaces:
        logging.info('Retrieving interface statistics...')
        int_stats = api.Networking.Interfaces.get_statistics(interfaces)
        logging.debug('int_stats =\n%s' % pformat(int_stats))
        if not ts:
            ts = ts_epoch(int_stats['time_stamp'])
        statistics = int_stats['statistics']
        for x in statistics:
            int_name = x['interface_name'].replace('.', '-')
            for y in x['statistics']:
                stat_name, stat_val = parse_statistic(statistic=y)
                stat_path = '%s.interface.%s.%s' % (prefix, int_name, stat_name)
                metric = (stat_path, (ts, stat_val))
                logging.debug('metric = %s' % str(metric))
                metrics.append(metric)
    return metrics


def get_trunk_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving list of trunks...')
    trunks = api.Networking.Trunk.get_list()
    logging.debug('trunks =\n%s' % pformat(trunks))
    if trunks:
        logging.info('Retrieving trunk statistics...')
        trunk_stats = api.Networking.Trunk.get_statistics(trunks)
        logging.debug('trunk_stats =\n%s' % pformat(trunk_stats))
        statistics = trunk_stats['statistics']
        if not ts:
            ts = ts_epoch(trunk_stats['time_stamp'])
        for x in statistics:
            trunk_name = x['trunk_name'].replace('.', '-')
            for y in x['statistics']:
                stat_name, stat_val = parse_statistic(statistic=y)
                stat_path = '%s.trunk.%s.%s' % (prefix, trunk_name, stat_name)
                metric = (stat_path, (ts, stat_val))
                logging.debug('metric = %s' % str(metric))
                metrics.append(metric)
    return metrics


def get_host_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving host statistics...')
    host_stats = api.System.Statistics.get_all_host_statistics()
    logging.debug('host_stats =\n%s' % pformat(host_stats))
    if not ts:
        ts = ts_epoch(host_stats['time_stamp'])
    statistics = host_stats['statistics']
    for x in statistics:
        host_id = x['host_id'].replace('.', '-')
        for y in x['statistics']:
            stat_name, stat_val = parse_statistic(statistic=y)
            if stat_name.startswith('memory_'):
                # throw memory stats into dedicated memory section
                stat_path = '%s.memory.%s.%s' % (prefix, host_id, stat_name)
            else:
                # catch-all
                stat_path = '%s.system.host.%s.%s' % (prefix, host_id, stat_name)
            metric = (stat_path, (ts, stat_val))
            logging.debug('metric = %s' % str(metric))
            metrics.append(metric)
    return metrics


def get_snat_pool_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving SNAT Pool statistics...')
    snatpool_stats = api.LocalLB.SNATPool.get_all_statistics()
    logging.debug('snatpool_stats = %s' % pformat(snatpool_stats))
    if not ts:
        ts = ts_epoch(snatpool_stats['time_stamp'])
    statistics = snatpool_stats['statistics']
    for x in statistics:
        snat_pool = x['snat_pool'].replace('.', '-')
        for y in x['statistics']:
            stat_name, stat_val = parse_statistic(statistic=y)
            stat_path = '%s.snat_pool.%s.%s' % (prefix, snat_pool, stat_name)
            metric = (stat_path, (ts, stat_val))
            logging.debug('metric = %s' % str(metric))
            metrics.append(metric)
    return metrics


def get_snat_translation_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving SNAT translation statistics...')
    snattrans_stats = api.LocalLB.SNATTranslationAddressV2.get_all_statistics()
    logging.debug('snattrans_stats = %s' % pformat(snattrans_stats))
    if not ts:
        ts = ts_epoch(snattrans_stats['time_stamp'])
    statistics = snattrans_stats['statistics']
    for x in statistics:
        trans_addr = x['translation_address'].replace('.', '-')
        for y in x['statistics']:
            stat_name, stat_val = parse_statistic(statistic=y)
            stat_path = '%s.snat_translation.%s.%s' % (prefix, trans_addr,
                                                       stat_name)
            metric = (stat_path, (ts, stat_val))
            logging.debug('metric = %s' % str(metric))
            metrics.append(metric)
    return metrics


def get_virtual_server_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving statistics for all virtual servers...')
    virt_stats = api.LocalLB.VirtualServer.get_all_statistics()
    logging.debug('virt_stats =\n%s' % pformat(virt_stats))
    if not ts:
        ts = ts_epoch(virt_stats['time_stamp'])
    statistics = virt_stats['statistics']
    for x in statistics:
        vs_name = x['virtual_server']['name'].replace('.', '-')
        for y in x['statistics']:
            stat_name, stat_val = parse_statistic(statistic=y)
            stat_path = '%s.vs.%s.%s' % (prefix, vs_name, stat_name)
            metric = (stat_path, (ts, stat_val))
            logging.debug('metric = %s' % str(metric))
            metrics.append(metric)
    return metrics


def get_pool_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving statistics for all pools...')
    pool_stats = api.LocalLB.Pool.get_all_statistics()
    logging.debug('pool_stats =\n%s' % pformat(pool_stats))
    if not ts:
        ts = ts_epoch(pool_stats['time_stamp'])
    statistics = pool_stats['statistics']
    for x in statistics:
        pool_name = x['pool_name'].replace('.', '-')
        for y in x['statistics']:
            stat_name, stat_val = parse_statistic(statistic=y)
            stat_path = '%s.pool.%s.%s' % (prefix, pool_name, stat_name)
            metric = (stat_path, (ts, stat_val))
            logging.debug('metric = %s' % str(metric))
            metrics.append(metric)
    logging.info('Retrieving pool list...')
    pool_list = api.LocalLB.Pool.get_list()
    logging.debug('pool_list =\n%s' % pformat(pool_list))
    if pool_list:
        logging.info('Retrieving active member count for all pools...')
        active_member_count = api.LocalLB.Pool.get_active_member_count(pool_names=pool_list)
        for pool_name, stat_val in zip(pool_list, active_member_count):
            stat_path = '%s.pool.%s.active_member_count' % (prefix, pool_name)
            metric = (stat_path, (ts, stat_val))
            logging.debug('metric = %s' % str(metric))
            metrics.append(metric)
        logging.info('Retrieving member count for all pools...')
        pool_members = api.LocalLB.Pool.get_member_v2(pool_names=pool_list)
        pool_member_count = [len(x) for x in pool_members]
        for pool_name, stat_val in zip(pool_list, pool_member_count):
            stat_path = '%s.pool.%s.member_count' % (prefix, pool_name)
            metric = (stat_path, (ts, stat_val))
            logging.debug('metric = %s' % str(metric))
            metrics.append(metric)
    return metrics


def get_pool_member_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving pool list...')
    pool_list = api.LocalLB.Pool.get_list()
    logging.debug('pool_list =\n%s' % pformat(pool_list))
    if pool_list:
        logging.info('Retrieving pool member statistics for all pools...')
        pool_member_stats = api.LocalLB.Pool.get_all_member_statistics(pool_names=pool_list)
        logging.debug('pool_member_stats =\n%s' % pformat(pool_member_stats))
        for pool_name, x in zip(pool_list, pool_member_stats):
            if not ts:
                ts = ts_epoch(x['time_stamp'])
            statistics = x['statistics']
            for y in statistics:
                pool_member_name = y['member']['address'].replace('.', '-')
                pool_member_port = y['member']['port']
                logging.debug('y = %s' % y)
                for z in y['statistics']:
                    stat_name, stat_val = parse_statistic(statistic=z)
                    stat_path = '%s.pool_member.%s.%s.%s.%s' % (prefix,
                                                                pool_name,
                                                                pool_member_name,
                                                                pool_member_port,
                                                                stat_name)
                    metric = (stat_path, (ts, stat_val))
                    logging.debug('metric = %s' % str(metric))
                    metrics.append(metric)
    return metrics


def get_node_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving node statistics...')
    node_stats = api.LocalLB.NodeAddressV2.get_all_statistics()
    logging.debug('node_stats =\n%s' % pformat(node_stats))
    if not ts:
        ts = ts_epoch(node_stats['time_stamp'])
    statistics = node_stats['statistics']
    for x in statistics:
        node_name = x['node'].replace('.', '-')
        for y in x['statistics']:
            stat_name, stat_val = parse_statistic(statistic=y)
            stat_path = '%s.node.%s.%s' % (prefix, node_name, stat_name)
            metric = (stat_path, (ts, stat_val))
            logging.debug('metric = %s' % str(metric))
            metrics.append(metric)
    return metrics


def get_irule_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving statistics for all iRules...')
    irule_stats = api.LocalLB.Rule.get_all_statistics()
    logging.debug('irule_stats =\n%s' % pformat(irule_stats))
    if not ts:
        ts = ts_epoch(irule_stats['time_stamp'])
    statistics = irule_stats['statistics']
    for x in statistics:
        irule_name = x['rule_name'].replace('.', '-')
        for y in x['statistics']:
            stat_name, stat_val = parse_statistic(statistic=y)
            stat_path = '%s.irule.%s.%s' % (prefix, irule_name, stat_name)
            metric = (stat_path, (ts, stat_val))
            logging.debug('metric = %s' % str(metric))
            metrics.append(metric)
    return metrics


def get_http_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving HTTP profile statistics...')
    http_stats = api.LocalLB.ProfileHttp.get_all_statistics()
    logging.debug('http_stats = %s\n' % pformat(http_stats))
    if not ts:
        ts = ts_epoch(http_stats['time_stamp'])
    statistics = http_stats['statistics']
    for x in statistics:
        profile_name = x['profile_name'].replace('.', '-')
        for y in x['statistics']:
            stat_name, stat_val = parse_statistic(statistic=y)
            stat_path = '%s.http.%s.%s' % (prefix, profile_name, stat_name)
            metric = (stat_path, (ts, stat_val))
            logging.debug('metric = %s' % str(metric))
            metrics.append(metric)
    return metrics


def get_oneconnect_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving OneConnect statistics...')
    oneconnect_stats = api.LocalLB.ProfileOneConnect.get_all_statistics()
    logging.debug('oneconnect_stats =\n%s' % pformat(oneconnect_stats))
    if not ts:
        ts = ts_epoch(oneconnect_stats['time_stamp'])
    statistics = oneconnect_stats['statistics']
    for x in statistics:
        profile_name = x['profile_name'].replace('.', '-')
        for y in x['statistics']:
            stat_name, stat_val = parse_statistic(statistic=y)
            stat_path = '%s.oneconnect.%s.%s' % (prefix, profile_name,
                                                 stat_name)
            metric = (stat_path, (ts, stat_val))
            logging.debug('metric = %s' % str(metric))
            metrics.append(metric)
    return metrics


def get_temperature_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving temperature statistics...')
    temperature_stats = api.System.SystemInfo.get_temperature_metrics()
    logging.debug('temperature_stats =\n%s' % pformat(temperature_stats))
    temperatures = temperature_stats['temperatures'][0]
    # not sure why this ^^ is a list, maybe for viprion platform?
    if not ts:
        ts = ts_epoch(temperature_stats['time_stamp'])
    for x in temperature_stats['temperatures']:
        logging.debug('x = %s' % x)
        temperature_index = None
        temperature_value = None
        for y in x:
            if y['metric_type'] == 'TEMPERATURE_INDEX':
                temperature_index = y['value']
            elif y['metric_type'] == 'TEMPERATURE_VALUE':
                temperature_value = y['value']
        stat_path = '%s.temperature.%s.temperature_value' % (prefix,
                                                             temperature_index)
        metric = (stat_path, (ts, temperature_value))
        logging.debug('metric = %s' % str(metric))
        metrics.append(metric)
    return metrics


def get_fan_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving fan statistics...')
    fan_stats = api.System.SystemInfo.get_fan_metrics()
    logging.debug('fan_stats =\n%s' % pformat(fan_stats))
    if not ts:
        ts = ts_epoch(fan_stats['time_stamp'])
    for x in fan_stats['fans']:
        logging.debug('x = %s' % x)
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
        stat_path = '%s.fan.%s.fan_state' % (prefix, fan_index)
        metric = (stat_path, (ts, fan_state))
        logging.debug('metric = %s' % str(metric))
        metrics.append(metric)
        stat_path = '%s.fan.%s.fan_speed' % (prefix, fan_index)
        metric = (stat_path, (ts, fan_speed))
        logging.debug('metric = %s' % str(metric))
        metrics.append(metric)
    return metrics


def get_device_group_metrics(api, prefix='', ts=None):
    if not ts:
        ts = timestamp_local()
    metrics = []
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
    logging.info('Retrieving device group list...')
    device_group_list = api.Management.DeviceGroup.get_list()
    logging.debug('device_group_list =\n%s' % pformat(device_group_list))
    if device_group_list:
        logging.info('Retrieving sync status of device groups...')
        device_sync_status = api.Management.DeviceGroup.get_sync_status(device_groups=device_group_list)
        logging.debug('device_sync_status =\n%s' % pformat(device_sync_status))
        for device_group, sync_status in zip(device_group_list, device_sync_status):
            device_group_name = device_group.replace('.', '-')
            stat_val = color_lookup[sync_status['color']]
            stat_path = '%s.device_group.%s.color' % (prefix, device_group_name)
            metric = (stat_path, (ts, stat_val))
            logging.debug('metric = %s' % str(metric))
            metrics.append(metric)
            stat_val = sync_lookup[sync_status['member_state']]
            stat_path = '%s.device_group.%s.member_state' % (prefix,
                                                             device_group_name)
            metric = (stat_path, (ts, stat_val))
            logging.debug('metric = %s' % str(metric))
            metrics.append(metric)
    return metrics


def get_web_acceleration_metrics(api, prefix='', ts=None):
    metrics = []
    logging.info('Retrieving web acceleration statistics...')
    web_accel_stats = api.LocalLB.ProfileWebAcceleration.get_all_statistics()
    logging.debug('web_accel_stats =\n%s' % pformat(web_accel_stats))
    if not ts:
        ts = ts_epoch(web_accel_stats['time_stamp'])
    statistics = web_accel_stats['statistics']

    for x in statistics:
        profile_name = x['profile_name'].replace('.', '-')
        for y in x['statistics']:
            stat_name, stat_val = parse_statistic(statistic=y)
            stat_path = '%s.web_acceleration.%s.%s' % (prefix, profile_name,
                                                       stat_name)
            metric = (stat_path, (ts, stat_val))
            logging.debug('metric = %s' % str(metric))
            metrics.append(metric)
    return metrics


def get_bigip_api(hostname, user, password, max_attempts=1, retry_sleep=1):
    last_error = ''
    for attempt in range(max_attempts):
        try:
            logging.info('Connecting to %s (try #%d/%d)...' %
                         (hostname, attempt + 1, max_attempts))
            api = bigsuds.BIGIP(hostname=hostname, username=user, password=password)
            logging.info('Requesting session...')
            api = api.with_session_id()
            logging.info('Setting recursive query state to enabled...')
            api.System.Session.set_recursive_query_state(state='STATE_ENABLED')
            logging.info('Switching active folder to /...')
            api.System.Session.set_active_folder(folder='/')
        except (bigsuds.ServerError, bigsuds.ConnectionError,
                bigsuds.ParseError, httplib.BadStatusLine), detail:
            last_error = detail
            logging.error('An error was encountered connecting to %s.' % hostname)
            logging.error(detail)
            logging.debug(traceback.format_exc())
            if attempt < max_attempts:  # don't sleep on last run
                logging.info('Sleeping %d seconds before retry...' % retry_sleep)
                sleep(retry_sleep)
        else:
            # no exception -- break out of for loop
            break
    else:
        logging.critical('Unable to collect metrics after %d attempts.' %
                         max_attempts)
        logging.critical('Last error: %s' % last_error)
        api = None
    return api


def get_bigip_metrics(api, categories, prefix, local_ts=False):
    metrics = []
    start_ts = timestamp_local()
    logging.debug('start_ts = %s' % start_ts)
    for category in categories:
        try:
            if local_ts:
                temp = globals()['get_' + category + '_metrics'](api, prefix, timestamp_local())
            else:
                temp = globals()['get_' + category + '_metrics'](api, prefix)
        except (bigsuds.ServerError, bigsuds.ConnectionError,
                bigsuds.ParseError, httplib.BadStatusLine), detail:
            logging.error('An exception was encountered: %s' % detail)
            logging.error(traceback.format_exc())
            logging.error('Skipping %s metrics.' % category)
            pass
        else:
            metrics.extend(temp)
    logging.info('%d metrics gathered.' % len(metrics))
    finish_ts = timestamp_local()
    logging.debug('finish_ts = %s' % finish_ts)
    collection_time = finish_ts - start_ts
    logging.info('Metrics gathered in %d seconds.' % collection_time)
    # add agent-related metrics if non-empty metrics list
    if metrics:
        stat_path = '%s.agent.collection_time' % prefix
        metric = (stat_path, (finish_ts, collection_time))
        logging.debug('metric = %s' % str(metric))
        metrics.append(metric)
        stat_path = '%s.agent.metric_count' % prefix
        metric = (stat_path, (finish_ts, len(metrics) + 1))  # include self
        logging.debug('metric = %s' % str(metric))
        metrics.append(metric)
    return metrics

