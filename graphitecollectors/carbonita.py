#!/usr/bin/python

# carbonita.py
# a lightweight library for carbon metric delivery

# Author: Matt Hite
# Email: mhite@hotmail.com
# 9/25/2013

import logging
import pickle
import socket
import struct
import time


def timestamp_local():
    """Return local epoch timestamp.

    Generate an integer epoch timestamp value of the current time.

    Returns:
        Integer of epoch timestamp.
    """
    epoch = int(time.time())
    logging.debug("epoch = %s" % epoch)
    return(epoch)


def chunks(l, n):
    """Yield successive n-sized chunks from l.

    Create a generator which yields successive n-sized chunks from l.

    Args:
        l: Sequence to chunk
        n: Chunk size

    Returns:
        A generator of chunked data.
    """
    for i in xrange(0, len(l), n):
        yield l[i:i+n]


def send_metrics(carbon_host, carbon_port, metric_list, chunk_size):
    """Sends metrics to a carbon server.

    Connects to a Carbon server and sends chunked metrics as
    a pickled data structure.

    Args:
        carbon_host: String hostname or IP of carbon server
        carbon_post: Integer port of carbon server
        metric_list: List of metrics to deliver to carbon server. Each element
            in the metric list is a tuple in the following format:
            (metric_name, (epoch_timestamp, value))
            where metric name is a string and epoch_timestamp and value are
            integers. For example:
            [('misc.metric1', (1380060284, 2545)),
             ('misc.metric2', (1380060300, 2535))]
        chunk_size: Integer representing number of items per pickled
            data payload

    Returns:
        None
    """
    # Break metric list into chunked list

    logging.info("Chunking metrics into chunks of %d..." % chunk_size)
    chunked_metrics = chunks(metric_list, chunk_size)

    # Transmit data to carbon server

    logging.info("Connecting to graphite at %s port %s..." % (carbon_host,
                                                              carbon_port))
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