#!/usr/bin/python

# Author: Matt Hite
# Email: mhite@hotmail.com

import json
import logging
from datetime import timedelta, tzinfo
from pprint import pformat
from time import time


class TZFixedOffset(tzinfo):
    """
    Fixed offset in minutes east from UTC.
    """
    def __init__(self, offset, name):
        self.__offset = timedelta(minutes=offset)
        self.__name = name

    def utcoffset(self, dt):
        return self.__offset

    def tzname(self, dt):
        return self.__name

    def dst(self, dt):
        return timedelta(0)


def timestamp_local():
    """Return local epoch timestamp.

    Generate an integer epoch timestamp value of the current time.

    Returns:
        Integer of epoch timestamp.
    """
    epoch = int(time())
    logging.debug('epoch = %s' % epoch)
    return epoch


def write_json_metrics(metric_list, filename):
    """Write JSON encoded metric_list to disk for later replay.
    """
    metric_list_json = json.dumps(metric_list)
    logging.debug('metric_list_json = %s' % pformat(metric_list_json))
    with open(filename, 'w') as f:
        f.write(metric_list_json)
