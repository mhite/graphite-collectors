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


class Carbon(object):
    """
    Carbon class.
    """
    _plaintext_default_port = 2003
    _pickle_default_port = 2004

    def __init__(self, host, port=None, encoding='plaintext'):
        """Initializes carbon object.

        Initializes the carbon object with connection and protocol encoding
        information. If port is not specified, will derive default based upon
        encoding.

        Args:
            host: String value specifying the carbon server.
            port: Integer value specifying the carbon port.
            encoding: String value specifying the carbon encoding protocol.
                Valid encodings include 'plaintext' and 'pickle'.

        Raises:
            ValueError
        """
        try:
            self._encode = getattr(self, '_%s_encode' % encoding.lower())
        except AttributeError:
            raise ValueError
        if port:
            self._port = port
        else:
            self._port = getattr(self, '_%s_default_port' % encoding.lower())
        self._host = host
        self._socket = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def _pickle_encode(self, metrics):
        """Pickles list of metrics.

        Prepares and pickles a list of metric objects for carbon delivery.

        Args:
            metric_list: List of metrics to pickle encode. Each element
                in the metric list is a tuple in the following format:
                (metric_name, (epoch_timestamp, value))
                where metric name is a string and epoch_timestamp and
                value are integers. For example:
                [('misc.metric1', (1380060284, 2545)),
                ('misc.metric2', (1380060300, 2535))]

        Returns:
            Carbon-compatible pickled data structure.
        """
        payload = pickle.dumps(metrics)
        header = struct.pack('!L', len(payload))
        data = header + payload
        return data

    def _plaintext_encode(self, metrics):
        """Plaintext encodes list of metrics.

        Prepares a plaintext string of metric objects for carbon delivery.

        Args:
            metrics: List of metrics to plaintext encode. Each element
                in the metric list is a tuple in the following format:
                (metric_name, (epoch_timestamp, value))
                where metric name is a string and epoch_timestamp and
                value are integers. For example:
                [('misc.metric1', (1380060284, 2545)),
                ('misc.metric2', (1380060300, 2535))]

        Returns:
            Carbon-compatible plaintext data structure.
        """
        data = str()
        for x in metrics:
            data += '%s %s %d\n' % (x[0], x[1][1], x[1][0])
        return data

    def _chunk_sequence(self, l, n):
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

    def connect(self):
        """Creates a socket to a carbon server."""
        self._socket = socket.create_connection((self._host, self._port))

    def send(self, metrics, chunk_size=None):
        """Sends metrics.

        Encodes and sends metrics to carbon server.

        Args:
            metrics: List of metric objects for carbon delivery.
            chunk_size: Integer value specifying number of metrics permitted
                per socket send operation. Default behavior sends all metrics
                in single socket call.
        """
        if not self._socket:
            self.connect()
        if chunk_size:
            chunked_metrics = self._chunk_sequence(metrics, chunk_size)
        else:
            chunked_metrics = [metrics]
        for chunk in chunked_metrics:
            data = self._encode(chunk)
            self._socket.sendall(data)

    def close(self):
        """Closes open socket to carbon server."""
        if self._socket:
            self._socket.close()
            self._socket = None


def timestamp_local():
    """Return local epoch timestamp.

    Generate an integer epoch timestamp value of the current time.

    Returns:
        Integer of epoch timestamp.
    """
    epoch = int(time.time())
    logging.debug("epoch = %s" % epoch)
    return(epoch)
