# ntpd-exporter
ntpd exporter for prometheus


## Instalation:

Make sure gpsd, prometheus and grafana are properly running. `gpsd-prometheus-exporter`needs `python3` and the following python libraries:

* [prometheus_client](https://github.com/prometheus/client_python)
* ntp-python libraries from ntpsec

To install:

	pip3 install prometheus_client
	pip3 install gps

	
If you want the `ntpd-exporter` to be loaded automatically by `systemd` please copy `ntpd_exporter.defaults` to 
`/etc/default/ntpd_exporter.defaults` and `ntpd_exporter.service` to `/lib/systemd/system`

	git clone git@github.com:brendanbank/ntpd-exporter.git
	cd ntpd-exporter
	sudo cp ntpd_exporter.defaults /etc/default
	sudo cp ntpd_exporter.service /lib/systemd/system
	sudo cp ntpd_exporter.py /usr/local/bin

	

ntpd_mon -- ntpd realtime monitor

  Created by Brendan Bank on 2021-01-12.
  Copyright 2021 Brendan Bank. All rights reserved.

  Licensed under the 3-Clause BSD License
  https://opensource.org/licenses/BSD-3-Clause

USAGE

positional arguments:
  host                  hosts to query [default: ['127.0.0.1']]

options:
  -h, --help            show this help message and exit
  -v, --verbose         set verbosity level [default: 0]
  -d, --debug           set Debug level [default: 0]
  -V, --version         show program's version number and exit
  --exporter-port EXPORTER_PORT
                        set TCP Port for the exporter server [default: 9014]
  --ntppool-hostname NTPPOOLHOST
                        set ntp pool hostname to query [default: []]
  --disable-offset-histogram
                        Disable ntp offset observations every 2 seconds
  --histogram-bucket-size OFFSET_BUCKET_SIZE
                        set lower bound histogram bucket [default: 2.5e-07]
  --histogram-bucket-count OFFSET_BUCKET_COUNT
                        set number of buckets for the ntp offset histogram
                        [default: 40]
	
