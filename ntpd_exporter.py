#! /usr/bin/env python3
#
# BSD 3-Clause License
#
# Copyright (c) 2021, Brendan Bank
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

'''
ntpd_exporter -- ntpd realtime monitor

ntpd_exporter is a exporter for prometheus

@author:     Brendan Bank

@copyright:  2021 Brendan Bank. All rights reserved.

@license:    BSD-3-Clause

@contact:    brendan.bank@gmail.com

@deffield    updated: Updated
'''

import ntp.control
import ntp.packet
import ntp.util
import ntp.poly
import cmd
import os
import sys
import socket
import json

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
import select


log = logging.getLogger(__name__)

__all__ = []
__version__ = 0.2
__date__ = '2021-01-12'
__updated__ = '2021-11-13'

DEBUG = 1
TESTRUN = 0
PROFILE = 0
EXPORTER_PORT = 9014

class MonitoringThread(threading.Thread):
    """ Base class for treaded monitors """
        
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
        """ poll to wait for the next scheduled event """
        
        if (time.time() >= self._run_at):
            self._run_at = self._run_at + self.POLL_INTERVAL

            if (time.time() >= self._run_at):
                self._run_at = time.time() + self.POLL_INTERVAL

            return (True)

        dtime = self._run_at - time.time()
        
        if (dtime > 0 and dtime < 1):
            self.log.debug(f'{self.name} run in {dtime:0.6f} seconds')
            time.sleep(dtime)

        else:
            self.log.debug(f'{self.name} run in {dtime:0.1f} seconds')
            time.sleep(self._sleep)
        
        return(False)

    
class NtpStats(MonitoringThread):
    """ read system """
    POLL_INTERVAL = 20
    
    def run(self):
        
        self.log.info (f'Thread run {self.name}')
        
        (host_metrics, remote_metrics) = NtpMetrics.init_host_metrics(self.registry)
        
        ntp_metrics = {}
        for hostname in self.args.hosts:
            ntp_metrics[hostname] = NtpMetrics(hostname=hostname,
                                                host_metrics=host_metrics,
                                                log=self.log,
                                                remote_metrics=remote_metrics
                                                )
        
        while (self.keep_running):
        
            if (self.poll()):
                
                for hostname, instance in ntp_metrics.items():
                    try:
                        self.log.info(f'{self.name}: fetched stats from {hostname}')
                        
                        session = NtpdConnect(hostname)
                        if not session:
                            continue
                        
                        instance.fetch(session)
                        
                        instance.peers(session)
                        removed = instance.remove_expired_remotes()

                        for s in removed:
                            for host in s:
                                if (len(host) != 0):
                                    self.log.info(f'{self.name}: removed remote {host[1]}')
                        
                    except NTPException as e:
                        self.log.error(f'{self.name}: error received {e}')


class MonitorPoolQuality(MonitoringThread):
    """ pull monitoring stats from the ntppool monitoring service """
    
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


class PacketStats(MonitoringThread):
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
        self.metrics = {}
        for k, v in self.DICTVAR.items():
            self.metrics[self.DICTVAR[k]] = Gauge(NtpMetrics.PREFIX + '_' + v,
                    f'sysstat variable {k}', ['timeserver'], registry=self.registry)
    
    def run(self):
        self.log.info (f'Thread run {self.name}')
        self.init_metrics()
        
        while (self.keep_running):
            if (self.poll()):
                self.log.debug(f'run {self.name}')
                for hostname in self.args.hosts:
                    self.get_packet_stats(hostname)

    def get_packet_stats(self, hostname):

        session = NtpdConnect(hostname)
        if not session:
            return (None)
            
        sysstat = NtpdSysStats(session)
        if not sysstat:
            return (None)


        for k in sysstat.stats:
            key = sysstat._ntpvars[k]
            ntpvar = self.DICTVAR[key]
            self.log.debug (f'key = {k} translate {key} to {ntpvar} = {sysstat.stats[k]}')
            if not sysstat.stats[k]:
                self.log.debug (f'key {key} == None')
            else:
                self.metrics[ntpvar].labels(hostname).set(sysstat.stats[k])

class ExporterDebug(MonitoringThread):
    """ read system """
    POLL_INTERVAL = 5
    
    def run(self):
        self.log.info (f'Thread run {self.name}')
        
        while (self.keep_running):
        
            if (self.poll()):
                self.log.debug(f'run {self.name}')
                
                # self.log.debug(generate_latest(registry=self.registry).decode())

class NtpMetricsException(Exception):
    """Exception raised by this module."""
    pass


class NTPException(Exception):
    """Exception raised by this module."""
    pass

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
            ntp_metrics = {}
            for hostname in self.args.hosts:
                ntp_metrics[hostname] = NtpMetrics(self.registry, log=self.log, hostname=hostname)

        while (self.keep_running):
        
            if (self.poll() and self.args.offset_histogram):
                self.log.debug(f'run {self.name} ')
                
                for hostname, metric in ntp_metrics.items():
                    try:
                        rt_metric_observed = metric.fetch_offset()
                        if not rt_metric_observed:
                            continue
                            
                        self.log.debug(f'rt_metric_observed: {rt_metric_observed}')
                        for key in rt_metrics.keys():
                            
                            self.log.debug(f'{self.name}: {key} fetched for hostname {hostname}: {rt_metric_observed[key]}')
                            rt_metrics[key].labels(hostname).observe(float(rt_metric_observed[key]))
                        
                    except NTPException as e:
                        self.log.error(f'{self.name}: error received {e}')


class NtpMetrics(object):
    
    HOST_CLOCK_VARIABLES = {
        'leap': 'leap indicator',
        'precision': 'log2 precision',
        'stratum': 'stratum',
        'offset': 'offset from refrence clock',
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
        # 'count': 'Remote count',
        }
    REMOTE_CLOCK_INFO = ['refid']

    def __init__(self, host_metrics=None,
                 remote_metrics=None,
                 hostname='localhost',
                 log=None,
                 timeout=1):
        
        self.hostname = hostname
        self._metrics = host_metrics
        self._remote_metrics = remote_metrics
        self._per_second_metrics = {}
        self.timeout = timeout
        self.log = log
        self._remotes = []
        self._hostname_cache = {}

    def fetch(self, session):


        readvar = NtpdReadVar(session).stats
        readclock = NtpdClockVar(session).stats

        for key in self.HOST_CLOCK_VARIABLES.keys():
            if not key in readvar or readvar[key] == None:
                continue
            self._metrics[key].labels(self.hostname).set(readvar[key])
        
        info_vars = {}
        for i in self.HOST_CLOCK_INFO:
            info_vars[i] = str(readvar[i]).replace('"', '')
        
        if readclock:
            for key, val in readclock.items():
                if val and key:
                    info_vars[key] = str(val)
        
        self._metrics['info'].labels(self.hostname).info(info_vars)

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
        [ JITTER_BUCKET.append(f'{i * (offset_bucket_size/2):0.9f}') for i in range(0 , int(offset_bucket_count)) ]
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

    def fetch_offset(self):
        session = NtpdConnect(self.hostname)
        if not session:
            return (None)

        readvar = NtpdReadVar(session).stats
        readvar['offset'] = float(readvar['offset']) / 1000
        readvar['sys_jitter'] = float(readvar['sys_jitter']) / 1000
        readvar['clk_jitter'] = float(readvar['clk_jitter']) / 1000
        readvar['clk_wander'] = float(readvar['clk_wander']) * 1000
        
        self.log.debug (f'readvar {readvar}')

        return(readvar)

    def peers(self, session):

        peers = collect_peer_varables(session)
        remotes = []
        for peer in peers:
        
            for key in self.REMOTE_CLOCK_VARIABLES.keys():
                if not key in peer['variables']:
                    self.log.debug (f'Err: {key} not in remote')
                    continue

                self._remote_metrics[key].labels(self.hostname, peer['host']).set(peer['variables'][key])
                self.log.debug (f'peer {peer["host"]} key = {key} value = {peer["variables"][key]}')
            self.log.debug (f'peer {peer}')
                        
            info_vars = {}
            info_vars["association_id"] = str(peer["associd"])
            info_vars["status"] = str(peer["status"])
            info_vars["condition"] = str(peer["condition"])
            info_vars["refid"] = str(peer["variables"]["refid"])

            self._remote_metrics['info'].labels(self.hostname, peer['host']).info(info_vars)
            
            remotes.append((self.hostname, peer['host']))
        
        self._remotes = remotes

    def remove_expired_remotes(self):
        keys = self.REMOTE_CLOCK_VARIABLES.keys()
        removed = set()
        for metric_key in keys:
            self.log.debug(f'metric_key = {metric_key}')
            metric = self._remote_metrics[metric_key]
            metric_remotes = []
            for host, remote in metric._metrics.keys():
                self.log.debug(f'compre sets host = {host} remote = {remote}')

                if (host == self.hostname):
                    metric_remotes.append((host, remote))
                    
            measured_remotes = self._remotes

            diff = frozenset(metric_remotes).difference(measured_remotes)
            for exporter_metric in diff:
                metric.remove(*exporter_metric)
        
            removed.add(diff)
            
        return(removed)


class NtpdStats:

    def collect_variables(self, variables, associd=0):
        response = []
        try:
            response = self.session.readvar(associd,
                                       variables,
                                       raw=False)
            return(response)
        
        except ntp.packet.ControlException as e:
            """ collect the variables one by one, there is one 
            var in the set not available """
            
            if ntp.control.CERR_UNKNOWNVAR == e.errorcode:
                print (e)
                for var in variables:
                    try:
                        item = self.session.readvar(0, [var], raw=False)
                        response.append((var, item[var]))
                        
                    except ntp.packet.ControlException as e:
                        """ variables not available, set to none"""
                        if ntp.control.CERR_UNKNOWNVAR == e.errorcode:
                            response.append((var, None))
                            continue
                        raise e
    
                return (ntp.util.OrderedDict(response)) 
            raise e
    
    def __init__(self, session, associd=0):
            
        self.session = session
        self.associd = associd
        
        self.stats = self.collect_variables([v for v in self._ntpvars.keys()], associd=associd)


class NtpdSysInfo(NtpdStats):
    _ntpvars = {
        "peeradr": "system peer",
        "peermode": "system peer mode",
        "leap": "leap indicator",
        "stratum": "stratum",
        "precision": "log2 precision",
        "rootdelay": "root delay",
        "rootdisp": "root dispersion",
        "rootdist": "root distance",
        "refid": "reference ID",
        "reftime": "reference time",
        "sys_jitter": "system jitter",
        "clk_jitter": "clock jitter",
        "clk_wander": "clock wander",
        "authdelay": "symm. auth. delay" }


class NtpdSysStats(NtpdStats):
    _ntpvars = {
        "ss_uptime": "uptime",
        "ss_numctlreq": "control requests",
        "ss_reset": "sysstats reset",
        "ss_received": "packets received",
        "ss_thisver": "current version",
        "ss_oldver": "older version",
        "ss_badformat": "bad length or format",
        "ss_badauth": "authentication failed",
        "ss_declined": "declined",
        "ss_restricted": "restricted",
        "ss_limited": "rate limited",
        "ss_kodsent": "KoD responses",
        "ss_processed": "processed for time",
    }


class NtpdKernInfo(NtpdStats):
    _ntpvars = {
        "koffset": "pll offset",
        "kfreq": "pll frequency",
        "kmaxerr": "maximum error",
        "kesterr": "estimated error",
        "kstflags": "kernel status",
        "ktimeconst": "pll time constant",
        "kprecis": "precision",
        "kfreqtol": "frequency tolerance",
        "kppsfreq": "pps frequency",
        "kppsstab": "pps stability",
        "kppsjitter": "pps jitter",
        "kppscalibdur": "calibration interval",
        "kppscalibs": "calibration cycles",
        "kppsjitexc": "jitter exceeded",
        "kppsstbexc": "stability exceeded",
        "kppscaliberrs": "calibration errors",
    }


class NtpdMonStats(NtpdStats):
    _ntpvars = {
        "mru_enabled": "enabled",
        "mru_hashslots": "hash slots in use",
        "mru_depth": "addresses in use",
        "mru_deepest": "peak addresses",
        "mru_maxdepth": "maximum addresses",
        "mru_mindepth": "reclaim above count",
        "mru_maxage": "reclaim maxage",
        "mru_minage": "reclaim minage",
        "mru_mem": "kilobytes",
        "mru_maxmem": "maximum kilobytes",
        "mru_exists": "alloc: exists",
        "mru_new": "alloc: new",
        "mru_recycleold": "alloc: recycle old",
        "mru_recyclefull": "alloc: recycle full",
        "mru_none": "alloc: none",
        "mru_oldest_age": "age of oldest slot",

}


class NtpdIOStats(NtpdStats):
    _ntpvars = {
        "iostats_reset": "time since reset",
        "total_rbuf": "receive buffers",
        "free_rbuf": "free receive buffers",
        "used_rbuf": "used receive buffers",
        "rbuf_lowater": "low water refills",
        "io_dropped": "dropped packets",
        "io_ignored": "ignored packets",
        "io_received": "received packets",
        "io_sent": "packets sent",
        "io_sendfailed": "packet send failures",
        "io_wakeups": "input wakeups",
        "io_goodwakeups": "useful input wakeups",
    }


class NtpdVar:
    """ Ntpd Base clasee for CTL_OP_READCLOCK and CTL_OP_READVAR """

    def __init__(self, session, associd=0):
            
        self.session = session
        self.associd = associd
        self.stats = None
        try:
            self.stats = session.readvar(self.associd, opcode=self._opcode, raw=False)
        except ntp.packet.ControlException as e:
            print (f"this host does not look like is has it's own clock {e}")
            


class NtpdClockVar(NtpdVar):
    _opcode = ntp.control.CTL_OP_READCLOCK


class NtpdReadVar(NtpdVar):
    _opcode = ntp.control.CTL_OP_READVAR

    
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


class GracefulKiller:
    kill_now = False

    def __init__(self):
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum, frame):
        self.kill_now = True


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
            'ntppool_monitor': MonitorPoolQuality,
            'ntp_debug': ExporterDebug,
            'ntp_offset_histogram': NtpOffsetHistogram,
            'ntp_host_stats': NtpStats,
            'ntp_packet_stats': PacketStats
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

    
def NtpdConnect(host, primary_timeout=1500, secondary_timeout=1000):
    
    hosts = []
    session = ntp.packet.ControlSession()
    session.primary_timeout = primary_timeout
    session.secondary_timeout = secondary_timeout
    hosts.append((host, session.ai_family))
    if not session.openhost(*hosts[0]):
        return (None)
    """ test if we can query the server """
    
    try:
        ntp_packet = queryhost(host, False)
        sys.stderr.write (f"ntp query: {ntp_packet}\n")
        if not ntp_packet:
            return (None)
    except ntp.packet.ControlException as e:
        sys.stderr.write (f"could not connect to host: {host} '{e}")
        return(None)
    
    return(session)

def queryhost(server, concurrent, timeout=1, port=123):
    "Query IP addresses associated with a specified host."
    af = socket.AF_UNSPEC
    try:
        iptuples = socket.getaddrinfo(server, port,
                                      af, socket.SOCK_DGRAM,
                                      socket.IPPROTO_UDP)
    except socket.gaierror as e:
        log("lookup of %s failed, errno %d = %s" % (server, e.args[0], e.args[1]))
        return []
    sockets = []
    packets = []
    request = ntp.packet.SyncPacket()
    request.transmit_timestamp = ntp.packet.SyncPacket.posix_to_ntp(
        time.time())
    packet = request.flatten()
    needgap = (len(iptuples) > 1) and (gap > 0)
    firstloop = True
    for (family, socktype, proto, canonname, sockaddr) in iptuples:
        if needgap and not firstloop:
            time.sleep(gap)
        if firstloop:
            firstloop = False
        s = socket.socket(family, socktype)
        try:
            s.sendto(packet, sockaddr)
        except socket.error as e:
            log("socket error on transmission: %s" % e)
            continue
        if concurrent:
            sockets.append(s)
        else:
            r, _, _ = select.select([s], [], [], timeout)
            if not r:
                return []
            read_append(s, packets, packet, sockaddr)
        while sockets:
            r, _, _ = select.select(sockets, [], [], timeout)
            if not r:
                return packets
            for s in sockets:
                read_append(s, packets, packet, sockaddr)
                sockets.remove(s)
    return packets

def read_append(s, packets, packet, sockaddr):
    d, a = s.recvfrom(1024)
    pkt = ntp.packet.SyncPacket(d)
    # pkt.hostname = server
    pkt.resolved = sockaddr[0]
    packets.append(pkt)
    return packets

def collect_peer_varables(session):
    peer_stat = []
    peers = session.readstat(0)

    for peer in peers:

        peer.variables = session.readvar(peer.associd, raw=False)

        if  'srchost' in peer.variables:
            host = peer.variables['srchost']
        else:
            host = (ntp.util.canonicalize_dns(peer.variables['srcadr']))
        
        peer_stat.append({'associd': peer.associd,
                               'status': peer.status,
                               'host': host,
                               'condition': ntp.util.PeerStatusWord(peer.status).condition,
                               'variables': peer.variables})

    return (peer_stat)


if __name__ == '__main__':
    main()
