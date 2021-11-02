#!/usr/bin/env python3
# Copyright 2021 Brendan Bank
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its
# contributors may be used to endorse or promote products derived
# from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

# Parts of this code came from ntpq.py - Python NTP control library by Peter C. Norton
###############################################################################
# ntpq.py - Python NTP control library.
# Copyright (C) 2016 Peter C. Norton (@pcn on github)
###############################################################################

'''
ntpd_exporter -- ntpd realtime monitor

ntpd_exporter is a exporter for prometheus

@author:     Brendan Bank

@copyright:  2021 Brendan Bank. All rights reserved.

@license:    BSD-3-Clause

@contact:    brendan.bank@gmail.com

@deffield    updated: Updated
'''

import socket
from prometheus_client import (Histogram, CollectorRegistry,
                               start_http_server, Gauge, Info,
                               generate_latest)
import time, datetime
import struct
import re
import sys, os
import logging
from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter
import threading
import queue
import requests
import csv
import signal
import pwd
import grp
import subprocess

log = logging.getLogger(__name__)

__all__ = []
__version__ = 0.1
__date__ = '2021-01-12'
__updated__ = '2021-01-12'

DEBUG = 1
TESTRUN = 0
PROFILE = 0
EXPORTER_PORT = 9014


def main(argv=None):  # IGNORE:C0111
    '''Command line options.'''

    if argv is None:
        argv = sys.argv
    else:
        sys.argv.extend(argv)

    program_name = os.path.basename(sys.argv[0])
    program_version = "v%s" % __version__
    program_build_date = str(__updated__)
    program_version_message = '%%(prog)s %s (%s)' % (program_version, program_build_date)
    program_shortdesc = __import__('__main__').__doc__.split("\n")[1]
    program_license = '''%s

  Created by Brendan Bank on %s.
  Copyright 2021 Brendan Bank. All rights reserved.

  Licensed under the 3-Clause BSD License
  https://opensource.org/licenses/BSD-3-Clause

USAGE
''' % (program_shortdesc, str(__date__))
    all_treads = {}
    # # Start logging
    tl = ThreadedLogger()
    
    try:
        # Setup argument parser
        parser = ArgumentParser(description=program_license, formatter_class=RawDescriptionHelpFormatter)
        parser.add_argument("-v", "--verbose", dest="verbose",
                            default=0, action="count", help="set verbosity level [default: %(default)s]")
        parser.add_argument("-d", "--debug", dest="debug",
                            default=0, action="count", help="set Debug level [default: %(default)s]")
        parser.add_argument('-V', '--version', action='version', version=program_version_message)
        parser.add_argument('--exporter-port', type=int, dest="exporter_port",
                            default=EXPORTER_PORT,
                            help="set TCP Port for the exporter server [default: %(default)s]")
        
        parser.add_argument("--ntppool-hostname", dest="ntppoolhost", action='append',
                            default=[], type=str, help="set ntp pool hostname to query [default: %(default)s]")
                
        parser.add_argument("--disable-offset-histogram", dest="offset_histogram",
                            default=True, action='store_false',
                            help="Disable ntp offset observations every 2 seconds")
        
        parser.add_argument("--histogram-bucket-size", type=float, dest="offset_bucket_size", default=0.00000025,
                            help="set lower bound histogram bucket [default: %(default)s]")
        
        parser.add_argument("--histogram-bucket-count", type=int, dest="offset_bucket_count", default=40,
                            help="set number of buckets for the ntp offset histogram [default: %(default)s]")

        parser.add_argument(dest="hosts", default=["127.0.0.1"],
                            help="hosts to query [default: %(default)s]",
                            nargs='*',
                            metavar="host")

        # Process arguments
        args = parser.parse_args()
        
        registry = CollectorRegistry()
        
        start_http_server(EXPORTER_PORT, registry=registry)
        tl.start()
        tl.debug(f'start with {args}')
        
        if (args.debug > 0):
            logging.basicConfig(format='%(message)s', stream=sys.stderr, level=logging.DEBUG)
        elif (args.verbose):
            logging.basicConfig(format='%(message)s', stream=sys.stderr, level=logging.INFO)
        else:
            logging.basicConfig(format='%(message)s', stream=sys.stderr, level=logging.WARNING)

        monitors = {
            'ntpq_monitor': MonitorPoolQuality,
            'ntpq_debug': ExporterDebug,
            'ntpq_offset_histogram': NtpOffsetHistogram,
            'ntpq_host_stats': NtpStats,
            'ntpq_packet_counter': PacketCounter
        }
        
        for mon in monitors.keys():
            all_treads[mon] = monitors[mon](mon, tl, registry, args)
            
        for mon in monitors.keys():
            all_treads[mon].start()

        time.sleep(1)
        
        drop_privileges()
        
        keep_running = True
        killer = GracefulKiller()
        while keep_running:
            time.sleep(1)
            if (killer.kill_now):
                tl.critical('kill signal recieved')
                break

            for mon in monitors.keys():
                if not all_treads[mon].is_alive():
                    tl.critical(f'{mon} not running')
                    keep_running = False
                    break

    except KeyboardInterrupt:
        ### handle keyboard interrupt ###
        pass
    except Exception as e:
        if DEBUG or TESTRUN:
            raise(e)
        indent = len(program_name) * " "
        sys.stderr.write(program_name + ": " + repr(e) + "\n")
        sys.stderr.write(indent + "  for help use --help")

    for t in all_treads.keys():
        all_treads[t].keep_running = False
        all_treads[t].log.info(f'signal thread stop: {t}')

    for t in all_treads.keys():
        all_treads[t].join()

    tl.keep_running = False
    tl.debug('stop log thread')
    tl.join()
    
    return (0)


class GracefulKiller:
    kill_now = False

    def __init__(self):
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum, frame):
        self.kill_now = True


class MonitoringThread(threading.Thread):
    
    def __init__(self, name, thread_logger, registry, args):
        threading.Thread.__init__(self)
        self.name = name
        self.args = args
        self.registry = registry
        self.log = thread_logger
        self.keep_running = True
        self.custom_queue = None
        self._run_at = time.time()
        self._sleep = 1
        
    def poll(self):

        if (time.time() >= self._run_at):
            self._run_at = self._run_at + self.POLL_INTERVAL

            if (time.time() >= self._run_at):
                self._run_at = time.time() + self.POLL_INTERVAL

            return (True)

        dtime = self._run_at - time.time()
        
        if ( dtime > 0 and dtime < 1):
            self.log.debug(f'{self.name} run in {dtime:0.6f} seconds')
            time.sleep(dtime)

        else:
            self.log.debug(f'{self.name} run in {dtime:0.1f} seconds')
            time.sleep(self._sleep)
        
        return(False)


class NtpOffsetHistogram(MonitoringThread):
    """ read system """
    POLL_INTERVAL = 2
    
    def run(self):
        self.log.info (f'Thread run {self.name}')
        
        if (self.args.offset_histogram):
            rt_metrics = NtpMetrics.init_histogram(self.registry,
                                                                 offset_bucket_size=self.args.offset_bucket_size,
                                                                 offset_bucket_count=self.args.offset_bucket_count
                                                                 )        
            ntpq_metrics = {}
            for hostname in self.args.hosts:
                ntpq_metrics[hostname] = NtpMetrics(self.registry, hostname=hostname)

        while (self.keep_running):
        
            if (self.poll() and self.args.offset_histogram):
                self.log.debug(f'run {self.name} ')
                
                for hostname, metric in ntpq_metrics.items():
                    try:
                        rt_metric_observed = metric.fetch_offset()
                        self.log.debug(f'rt_metric_observed: {rt_metric_observed}')
                        for key in rt_metrics.keys():
                            
                            self.log.debug(f'{self.name}: {key} fetched for hostname {hostname}: {rt_metric_observed[key]}')
                            rt_metrics[key].labels(hostname).observe(float(rt_metric_observed[key]))
                        
                    except NTPException as e:
                        self.log.error(f'{self.name}: error received {e}')

                    
class NtpStats(MonitoringThread):
    """ read system """
    POLL_INTERVAL = 20
    
    def run(self):
        
        self.log.info (f'Thread run {self.name}')
        
        (host_metrics, remote_metrics) = NtpMetrics.init_host_metrics(self.registry)
        
        ntpq_metrics = {}
        for hostname in self.args.hosts:
            ntpq_metrics[hostname] = NtpMetrics(hostname=hostname,
                                                host_metrics=host_metrics,
                                                remote_metrics=remote_metrics
                                                )
        
        while (self.keep_running):
        
            if (self.poll()):
                
                for hostname, instance in ntpq_metrics.items():
                    try:
                        self.log.info(f'{self.name}: fetched stats from {hostname}')
                        instance.fetch()
                        instance.peers()
                        removed = instance.remove_expired_remotes()
                        
                        for s in removed:
                            for host in s:
                                if (len(host) != 0):
                                    self.log.info(f'{self.name}: removed remote {host[1]}')
                        
                    except NTPException as e:
                        self.log.error(f'{self.name}: error received {e}')
                
class PacketCounter(MonitoringThread):
    """ read system """
    POLL_INTERVAL = 10
    
    DICTVAR = {
        "uptime": "uptime",
        "sysstats reset": "reset",
        "packets received": "packet_rx",
        "current version": "curr_version",
        "older version": "older_vesion",
        "bad length or format": "bad_len",
        "authentication failed": "auth_failed",
        "declined": "declined",
        "restricted": "restricted",
        "rate limited": "rate_limited",
        "KoD responses": "kod",
        "control requests": "control_requests",
        "processed for time": "proc_for_time"
        }
    
    def init_metrics(self):
        self.metrics={}
        for k,v in self.DICTVAR.items():
            self.metrics[self.DICTVAR[k]] = Gauge(NtpMetrics.PREFIX + '_' + v, 
                    f'sysstat variable {k}', ['timeserver'], registry=self.registry)
        self.ntpq = None
        for f in ["/usr/sbin/ntpq","/usr/bin/ntpq","/usr/local/bin/ntpq"]:
            if (os.path.exists(f)):
                self.ntpq = f
                break
                
    
    def run(self):
        self.log.info (f'Thread run {self.name}')
        self.init_metrics()
        
        while (self.keep_running):
            if (self.poll()):
                self.log.debug(f'run {self.name}')
                for hostname in self.args.hosts:
                    self.get_packet_stats(hostname)

    def get_packet_stats(self,hostname):
        
        proc = subprocess.Popen([self.ntpq, '-c', 'sysstat', hostname], stdout=subprocess.PIPE)
    
        while True:
            line = proc.stdout.readline().decode()
            if not line:
                break
            line = line.rstrip()

            self.log.debug(f'{self.name} line = {line}')
            (k,v) = line.rstrip().split(':')
            k = k.lstrip()
            v = v.lstrip()

            if (k in self.DICTVAR.keys()):
                ntpvar = self.DICTVAR[k]
                self.metrics[ntpvar].labels(hostname).set(v)
                

class ExporterDebug(MonitoringThread):
    """ read system """
    POLL_INTERVAL = 5
    
    def run(self):
        self.log.info (f'Thread run {self.name}')
        
        while (self.keep_running):
        
            if (self.poll()):
                self.log.debug(f'run {self.name}')
                
                #self.log.debug(generate_latest(registry=self.registry).decode())


class MonitorPoolQuality(MonitoringThread):
    POLL_INTERVAL = 500

    def run(self):
        self.log.info (f'Thread run {self.name}')
        self.NTPPOOL_QUALITY = Gauge(NtpMetrics.PREFIX + '_ntp_pool_quality_score',
                                     'NTP Pool monitor Quality Score',
                                     ['ntp_pool_host', 'monitor_id', 'monitor_name'],
                                     registry=self.registry)
        self.NTPPOOL_OFFSET = Gauge(NtpMetrics.PREFIX + '_ntp_pool_offset',
                                    'NTP Pool monitor offset',
                                    ['ntp_pool_host', 'monitor_id', 'monitor_name'],
                                    registry=self.registry)
        
        while (self.keep_running):
            if (self.poll()):
                self.log.info(f'run {self.name} get_quality_score')
                self.get_quality_score()
        
    def get_quality_score(self):
        if not self.args.ntppoolhost:
            return (None)
        
        for hostname in self.args.ntppoolhost:
        
            URL = f'https://www.ntppool.org/scores/{hostname}/log?limit=1&monitor=*'
    
            try:
                r = requests.get(URL)
            except Exception as e:
                self.log.error (f'error connecting to url: {URL}: {e}')
                continue
    
            if r.content:
                data = r.content.decode().split('\n')
    
                rows = list(csv.reader(data))
                (ts_epoch, ts, offset, step, score, monitor_id, monitor_name, leap, error) = rows.pop(1)
                self.log.info (f'feteched {URL}, with ts_epoch {ts_epoch}, ts {ts}, offset {offset}, step {step}' + 
                       f', score {score}, monitor_id {monitor_id}, monitor_name{monitor_name}, leap {leap}, error {error}')
    
                self.NTPPOOL_QUALITY.labels(hostname, monitor_id, monitor_name).set(score)
                self.NTPPOOL_OFFSET.labels(hostname, monitor_id, monitor_name).set(offset)
                
    
class NTP:
    """Helper class defining constants."""
    _SYSTEM_EPOCH = datetime.date(*time.gmtime(0)[0:3])
    """system epoch"""
    _NTP_EPOCH = datetime.date(1900, 1, 1)
    """NTP epoch"""
    NTP_DELTA = (_SYSTEM_EPOCH - _NTP_EPOCH).days * 24 * 3600
    """delta between system and NTP time"""
    
    NTP_PEER_SELECTION = {
        '0': 'reject',
        '1': 'falsetick',
        '2': 'excess',
        '3': 'outlier',
        '4': 'candidate',
        '5': 'backup',
        '6': 'sys.peer',
        '7': 'pps.peer',
        }

    CONTROL_PACKET_FORMAT = "!B B H H H H H"
    """ packet format to pack/unpack the control header"""
    
    NTP_CONTROL_OPCODES = {
        "readstat": 1,
        "readvar": 2,
        "readclock": 4
    }


class NtpMetricsException(Exception):
    """Exception raised by this module."""
    pass


class NTPException(Exception):
    """Exception raised by this module."""
    pass


class ThreadedLogger(threading.Thread):
    
    def __init__(self):
        threading.Thread.__init__(self)
        self._queue = queue.SimpleQueue()
        self.keep_running = True
        self.log = self

    def warning(self, msg):
        self._queue.put({'msg': f'Warn {msg}', 'level':log.warning})

    def error(self, msg):
        self._queue.put({'msg': f'Error {msg}', 'level':log.error})
        
    def info(self, msg):
        self._queue.put({'msg': f'Info {msg}', 'level':log.info})

    def debug(self, msg):
        self._queue.put({'msg': f'Debug {msg}', 'level':log.debug})

    def critical(self, msg):
        self._queue.put({'msg': f'Crit {msg}', 'level':log.critical})
        
    def run(self):
        log.info('log thread started')
        while (self.keep_running):
            item = self._queue.get(True)
            if (item):
                item['level'](item['msg'])
        
        log.info('log thread exited')


class NtpMetrics(object):
    
    HOST_CLOCK_VARIABLES = {
        'leap': 'leap indicator',
        'precision': 'log2 precision',
        'stratum': 'stratum',
        'offset': 'offset from refrende clock',
        'rootdelay': 'root delay',
        'rootdisp': 'root dispersion',
        'sys_jitter': 'system jitter',
        'clk_jitter': 'clock jitter',
        'clk_wander': 'clock wander',
        'frequency': 'frequency',
        'tai': 'tai',
        'mode': 'mode',
        'count': 'count',
        'stratum': 'stratum',
        }
    
    PREFIX = 'ntp'
    HOST_CLOCK_INFO = ['version', 'processor', 'system', 'refid']
    HOST_CLOCK_INFO_READCLOCK = ['name', 'fudgetime1', 'device', 'refid']
    
    REMOTE_CLOCK_VARIABLES = {
        'jitter': 'Remote Jitter',
        'offset': 'Remote Offset',
        'delay': 'Remote Delay',
        'precision': 'Remote precision',
        'rootdisp': 'Remote rootdisp',
        'rootdelay': 'Remote rootdelay',
        'count': 'Remote count',
        }
    REMOTE_CLOCK_INFO = ['refid', 'association_id', 'clocksource', 'peer_selection']

    def __init__(self, host_metrics=None,
                 remote_metrics=None,
                 hostname='localhost',
                 timeout=1):
        self.hostname = hostname
        self._metrics = host_metrics
        self._remote_metrics = remote_metrics
        self._per_second_metrics = {}
        self.timeout = timeout
        self._remotes = []
        self._hostname_cache = {}

    @classmethod
    def init_host_metrics (self, registry):
        
        hostmetrics = {}
        remote_metrics = {}
        # # host clock metrics
        for metric, description in self.HOST_CLOCK_VARIABLES.items():
            hostmetrics[metric] = Gauge(self.PREFIX + '_' + metric,
                                               description,
                                               ['timeserver'],
                                               registry=registry
                                            )
        hostmetrics['info'] = Info(self.PREFIX + '_detail', 'Description of the server', ['timeserver'],
                                     registry=registry)
        # peer metrics
        for metric, description in self.REMOTE_CLOCK_VARIABLES.items():
            
            remote_metrics[metric] = Gauge(self.PREFIX + '_remote_' + metric,
                                                  description,
                                                  ['timeserver', 'remote'],
                                                  registry=registry
                                                  )
        remote_metrics['info'] = Info(self.PREFIX + '_remote_detail',
                                            'Description of the remote timeserver', ['timeserver', 'remote'],
                                     registry=registry)
        
        return(hostmetrics, remote_metrics)
    
    @classmethod
    def init_histogram(self, registry, offset_bucket_size=1e-07, offset_bucket_count=40):
        OFFSET_BUCKETS = []
        OFFSET_BUCKETS.append(float("-inf"))
        [ OFFSET_BUCKETS.append(f'{i * offset_bucket_size:0.9}') for i in range(int(offset_bucket_count / -2), int(offset_bucket_count / 2) + 1)]
        OFFSET_BUCKETS.append(float("inf"))
        init_metrics = {}
        init_metrics['offset'] = Histogram(self.PREFIX + '_offset_histogram', 'Offset Histogram',
                                                    ['timeserver'], buckets=OFFSET_BUCKETS, registry=registry)
        
        JITTER_BUCKET = []
        JITTER_BUCKET.append(float("-inf"))
        [ JITTER_BUCKET.append(f'{i * (offset_bucket_size/2):0.9f}') for i in range(0 ,int(offset_bucket_count)) ]
        JITTER_BUCKET.append(float("inf"))
        
        init_metrics['sys_jitter'] = Histogram(self.PREFIX + '_sys_jitter_histogram', 'System Jitter Histogram',
                                                    ['timeserver'], buckets=JITTER_BUCKET, registry=registry)
        
        init_metrics['clk_jitter'] = Histogram(self.PREFIX + '_clk_jitter_histogram', 'Clock Jitter Histogram',
                                                    ['timeserver'], buckets=JITTER_BUCKET, registry=registry)
        
        WANDER_BUCKETS = []
        [ WANDER_BUCKETS.append(f'{i * 0.25}') for i in range(1, int(offset_bucket_count))]
        WANDER_BUCKETS.append(float("inf"))
        init_metrics['clk_wander'] = Histogram(self.PREFIX + '_clk_wander_histogram', 'Clock Wander Histogram PPB',
                                            ['timeserver'], buckets=WANDER_BUCKETS, registry=registry)

        
        return(init_metrics)
        
    def generate_latest_metrics(self):
        return (generate_latest(registry=self.registry).decode())
    
    def fetch(self):
        readvar = self._cmd_readvar()
        readclock = self._cmd_readclock()

        for key in self.HOST_CLOCK_VARIABLES.keys():
            if not key in readvar:
                continue
            self._metrics[key].labels(self.hostname).set(readvar[key])
        
        info_vars = {i:str(readvar[i]).replace('"', '') for i in self.HOST_CLOCK_INFO}
        
        if readclock:
            for key, val in readclock.items():
                if val and key:
                    info_vars[key] = val
            
        self._metrics['info'].labels(self.hostname).info(info_vars)

    def fetch_offset(self):
        readvar = self._cmd_readvar()
        readvar['offset'] = float(readvar['offset']) / 1000
        readvar['sys_jitter'] = float(readvar['sys_jitter']) / 1000
        readvar['clk_jitter'] = float(readvar['clk_jitter']) / 1000
        readvar['clk_wander'] = float(readvar['clk_wander']) * 1000
        
        return(readvar)
        
    def peers(self):
        ntpdict = self._composite_assoc_and_peer()
        remotes = []
        for remote in ntpdict:
            if remote['srcadr'] == '0.0.0.0':  # ntppool
                continue

            if remote['srcadr'].find('127.127') >= 0:
                remote['srcadr'] = f"{remote['refid']}(0)"
            else:
                remote['srcadr'] = f"{self._resolve(remote['srcadr'])} ({remote['srcadr']})"
                
            for key in self.REMOTE_CLOCK_VARIABLES.keys():
                if not key in remote:
                    print (f'Err: {key} not in remote')
                    continue
                
                self._remote_metrics[key].labels(self.hostname, remote['srcadr']).set(remote[key])
            
            info_vars = {i:str(remote[i]).replace('"', '') for i in self.REMOTE_CLOCK_INFO}
            
            self._remote_metrics['info'].labels(self.hostname, remote['srcadr']).info(info_vars)
            remotes.append((self.hostname, remote['srcadr']))
        self._remotes = remotes

    def _composite_assoc_and_peer(self):
        """
        returns a list of associations from the host,
        combined with the peer data.
        This data is a mixture of the data that is gotten
        from the commands 'ntpq -c pe' and 'ntpq -c as'
        This was my main goal in writing this.
        """
        # ncc = NTPControlClient()
        # ncp = ncc.request(host, op="readstat")
        data = list()
        ncp_data = self._ntp_control_request(op="readstat")
        for assoc in ncp_data['associations']:
            readvar_data = self._ntp_control_request(
                op="readvar", association_id=assoc['association_id'])
            for key, val in assoc.items():
                readvar_data[key] = str(val).rstrip("\x00")
                if key == 'peer_selection':
                    readvar_data[key] = NTP.NTP_PEER_SELECTION[readvar_data[key]]
    
            data.append(readvar_data)
        return data

    def _resolve(self, ip):
        
        #ip = f'{ip}2'
        
        timeout = socket.getdefaulttimeout() 
        socket.setdefaulttimeout(1)

        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self._hostname_cache[ip] = hostname
        except Exception:
            if ip in self._hostname_cache:
                hostname = self._hostname_cache[ip]
                
            else:
                hostname = ip
        
        socket.setdefaulttimeout(timeout)

        return(hostname)
    
    def _cmd_readclock(self):
        ncp_data = self._ntp_control_request(op="readclock")
        data = {}
        for key, value in ncp_data.items():
            data[key] = str(value).rstrip('\x00')
        
        return data

    def _cmd_readvar(self):
        ncp_data = self._ntp_control_request(op="readvar")
        data = {}
        for key, value in ncp_data.items():
            data[key] = str(value).rstrip('\x00')
        
        int_part, frac_part = [ int(x, 16) for x in ncp_data['clock'].split(".") ]
        ncp_data['clock'] = self._ntp_to_system_time(
            int_part + float(frac_part) / 2 ** 32
            )  # pylint: disable=protected-access

        return data
    
    def _ntp_to_system_time(self, timestamp):
        """Convert a NTP time to system time.
    
        Parameters:
        timestamp -- timestamp in NTP time
    
        Returns:
        corresponding system time
        """
        return timestamp - NTP.NTP_DELTA

    def _ntp_control_request(self, version=2, port='ntp',  # pylint: disable=too-many-arguments,invalid-name
                            op="readvar", association_id=0):
        """Query a NTP server.
        Parameters:
        version -- NTP version to use
        port    -- server port
        Returns:
        dictionary with ntp control info.  Specific data will vary based on the request type.
        """
        # lookup server address
        addrinfo = socket.getaddrinfo(self.hostname, port)[0]
        family, sockaddr = addrinfo[0], addrinfo[4]
    
        # create the socket
        sock = socket.socket(family, socket.SOCK_DGRAM)
    
        try:
            sock.settimeout(self.timeout)
    
            # create a control request packet
            sock.sendto(
                self._control_data_payload(
                    op=op, version=version,
                    association_id=association_id),
                sockaddr)
    
            # wait for the response - check the source address
            src_addr = None,
            while src_addr[0] != sockaddr[0]:
                response_packet, src_addr = sock.recvfrom(512)
    
            # build the destination timestamp
            # dest_timestamp = ntplib.system_to_ntp_time(time.time())
        except socket.timeout:
            raise NTPException("No response received from %s." % self.hostname)
        finally:
            sock.close()
    
        packet_dict = self._control_packet_from_data(response_packet)
        return packet_dict

    def _control_data_payload(self, version=2, op='readstat', association_id=0, sequence=1):
        """Convert the requested arguments into a buffer that can be sent over a socket.
        to an ntp server.
        Returns:
        buffer representing this packet
        Raises:
        NTPException -- in case of invalid field
        """
        leap = 0  # leap second indicator
        version = version  # protocol version
        mode = 6  # mode 6 is the control mode
        response_bit = 0  # request
        error_bit = 0
        more_bit = 0
        opcode = NTP.NTP_CONTROL_OPCODES[op]
        sequence = sequence
        status = 0
        association_id = association_id
        offset = 0
        count = 0
        try:
            packed = struct.pack(
                NTP.CONTROL_PACKET_FORMAT,
                (leap << 6 | version << 3 | mode),
                (response_bit << 7 | error_bit << 6 | more_bit << 5 | opcode),
                sequence,
                status,
                association_id,
                offset,
                count)
            return packed
        except struct.error:
            raise NTPException("Invalid NTP packet fields.")

    def _decode_association(self, data):
        """
        Provided a 2 uchar of data, unpack the first uchar of associationID,
        and the second uchar of association data from that uchar
        test with  e.g. data set to:
        In [161]: struct.pack("!B B", 0b00010100,0b00011010)
        Out[161]: '\x14\x1a'
        This is the data for a single association.
        """
        unpacked = struct.unpack("!H B B", data)
    
        return {
            'association_id': unpacked[0],
            'peer_config': unpacked[1] >> 7 & 0x1,
            'peer_authenable': unpacked[1] >> 6 & 0x1,
            'peer_authentic': unpacked[1] >> 5 & 0x1,
            'peer_reach': unpacked[1] >> 4 & 0x1,
            'reserved': unpacked[1] >> 3 & 0x1,
            'peer_selection': unpacked[1] & 0x7,
            'peer_event_counter': unpacked[2] >> 4 & 0xf,
            'peer_event_code': unpacked[2] & 0xf
        }

    def _control_packet_from_data(self, data):
        """Populate this instance from a NTP packet payload received from
        the network.
        Parameters:
        data -- buffer payload
        Returns:
        dictionary of control packet data.
        Raises:
        NTPException -- in case of invalid packet format
        """
    
        def decode_readstat(header_len, data, rdata):
            """
            Decodes a readstat request.  Augments rdata with
            association IDs from data
            """
            rdata['associations'] = list()
            for offset in range(header_len, len(data), 4):
                assoc = data[offset:offset + 4]
                association_dict = self._decode_association(assoc)
                rdata['associations'].append(association_dict)
            return rdata
    
        def decode_generic(header_len, data, rdata):
            
            buf = data[header_len:].decode().split(",")
            if (buf == ''):
                return None
            
            for field in buf:
    
                if ('=' in field):
                    try:
                        key, val = field.replace("\r\n", "").lstrip().split("=")
                    except ValueError as e:
                        print (f'cannot split by "=" field: "{field}" Error: {e}')
                        continue
                     
                    if (key == 'device'):
                        val = re.sub(r'\d+$', '', val)
                    val = val.replace("\"", "")
                else:
                    val = None
                    key = field.replace("\r\n", "").lstrip()
                    
                if key in ('rec', 'reftime'):
                    int_part, frac_part = [ int(x, 16) for x in val.split(".") ]
                    rdata[key] = self._ntp_to_system_time(
                        to_time(int_part, frac_part))  # pylint: disable=protected-access
                else:
                    rdata[key] = val
            return(rdata)
        
        def decode_readvar(header_len, data, rdata):
            """
            Decodes a redvar request.  Augments rdata dictionary with
            the textual data int he data packet.
            """

            def to_time(integ, frac, n=32):  # pylint: disable=invalid-name
                """Return a timestamp from an integral and fractional part.
                Having this here eliminates using an function internal to
                ntplib.
                Parameters:
                integ -- integral part
                frac  -- fractional part
                n     -- number of bits of the fractional part
                Retuns:
                float seconds since the epoch/ aka a timestmap
                """
                return integ + float(frac) / 2 ** n
    
            buf = data[header_len:].decode().split(",")
            for field in buf:
    
                if ('=' in field):
                    key, val = field.replace("\r\n", "").lstrip().split("=")
                else:
                    val = None
                    key = field.replace("\r\n", "").lstrip()
    
                if key in ('rec', 'reftime'):
                    int_part, frac_part = [ int(x, 16) for x in val.split(".") ]
                    rdata[key] = self._ntp_to_system_time(
                        to_time(int_part, frac_part))  # pylint: disable=protected-access
                else:
                    rdata[key] = val
                    
            # For the equivalent of the 'when' column, in ntpq -c pe
            # I believe that the time.time() minus the 'rec' matches that value.
            if 'rec' in rdata:
                rdata['when'] = time.time() - rdata['rec']
            return rdata
    
        try:
            header_len = struct.calcsize(NTP.CONTROL_PACKET_FORMAT)
            unpacked = struct.unpack(NTP.CONTROL_PACKET_FORMAT, data[0:header_len])
        except struct.error:
            raise NTPException("Invalid NTP packet.")
    
        # header status
        rdata = {
            "leap_header": unpacked[0] >> 6 & 0x1,
            "version": unpacked[0] >> 3 & 0x7,
            "mode": unpacked[0] & 0x7,  # end first uchar
            "response_bit": unpacked[1] >> 7 & 0x1,
            "error_bit": unpacked[1] >> 6 & 0x1,
            "more_bit": unpacked[1] >> 5 & 0x1,
            "opcode": unpacked[1] & 0x1f,  # end second uchar
            "sequence": unpacked[2],
            "leap": unpacked[3] >> 14 & 0x1,
            "clocksource": unpacked[3] >> 8 & 0x1f,  # 6 bit mask
            "system_event_counter": unpacked[3] >> 4 & 0xf,
            "system_event_code": unpacked[3] & 0xf,  # End first ushort
            "association_id": unpacked[4],
            "offset": unpacked[5],
            "count": unpacked[6]
        }
    
        opcodes_by_number = { v:k for k, v in NTP.NTP_CONTROL_OPCODES.items() }
        if opcodes_by_number[rdata['opcode']] == "readstat":
            return decode_readstat(header_len, data, rdata)
        elif opcodes_by_number[rdata['opcode']] == "readvar":
            return decode_readvar(header_len, data, rdata)
        elif opcodes_by_number[rdata['opcode']] == "readclock":
            rdata = {}
            return decode_generic(header_len, data, rdata)

    def remove_expired_remotes(self):
        keys = self.REMOTE_CLOCK_VARIABLES.keys()
        removed = set()
        for metric_key in keys:
            metric = self._remote_metrics[metric_key]
            metric_remotes = []
            for host, remote in metric._metrics.keys():
                if (host == self.hostname):
                    metric_remotes.append((host, remote))
                    
            measured_remotes = self._remotes

            diff = frozenset(metric_remotes).difference(measured_remotes)
            for exporter_metric in diff:
                metric.remove(*exporter_metric)
        
            removed.add(diff)
            
        return(removed)


def drop_privileges(uid_name='nobody', gid_name='nogroup'):
    if os.getuid() != 0:
        # We're not root so, like, whatever dude
        return
 
    # Get the uid/gid from the name
    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid
 
    # Remove group privileges
    os.setgroups([])
 
    # Try setting the new uid/gid
    os.setgid(running_gid)
    os.setuid(running_uid)
 
    # Ensure a very conservative umask
    old_umask = os.umask(0o077)


if __name__ == '__main__':
    main()
