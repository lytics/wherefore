
Wherefore
---------

Wherefore art thy transfering 1GB/s to a Chinese IP block?

# Project under construction!

There is no current release but progress is being made towards that goal. Stay tuned for more. Master should not be considered stable yet!

## Still TODO:

* [ ] Better Documentation
* [ ] Use Gopacket's network interface
  * [ ] Simplify the interface with libpcap/network interface
* [ ] More alerting mechanisms(OpsGenie, PagerDuty, Webhook, etc)


## Project Goals

* Monitor the network interfaces of a host for anomylous network traffic and connections 24/7
  * Useful as a non-daemon handy network traffic analysis tool!
* Efficient and low overhead monitoring; minimize processor and memory consumption 
* Concurrent processing of network traffic IP flows
* Ability to send alert notifications when anomalous traffic is detected

Wherefore is a fork of the TCP attack detection system [Honey Badger](https://github.com/david415/HoneyBadger) created by [David Stainton](https://github.com/david415). A large amount of credit goes to David for building the interface with libpcap. It was used as a base to prototype the basic functionality desired; then layers of the original onion have been peeled back when appropriate. 

The project has been developed and tested for Debian systems. No reason it couldn't run on Fedora/RedHat or libpcap capable systems, but there's a potential for errors on untested systems and configuration.

 
### Operation

Overview: Wherefore listens to libpcap and checks all packets traveling over the interface and groups them by IP based flows and tracks bytes transfered per flow. This data is processed by fully configurable [Lytics Anomalyzer Project](https://github.com/lytics/anomalyzer) to detect excessive or unusual traffic. 

In the case that anomalous traffic is detected, alerts are logged or optionaly sent to an external notification service(Slack, PagerDuty, OpsGenie..etc).

Wherefore can also be used to expose what processes are holding connections open. By setting anomalyzer to be extremely sensitive.


### Configuration

There are a lot of options, and they are currently all configured via command line arguments to the process.


```
Usage of ./wherefore:
  -anom_active_size=1: Anomalyzer Active Size
  -anom_gv_cap=10: Number of data points to run anomalyzer test over
  -anom_lower_bound=5e-324: Anomolyzer LowerBound for Fencing
  -anom_methods="diff,fence,highrank,lowrank,magnitude": Anomalyzer algorithms to test, written in csv format. eg: diff,fence,etc
  -anom_n_seasons=4: Anomalyzer N Seasons variable
  -anom_sensitivity=2: Anomalyzer sensetivity
  -anom_upper_bound=5: Anomalyzer UpperBound for Fencing
  -archive_dir="": archive directory for storing attack logs and related pcap files
  -daq="libpcap": Data AcQuisition packet source
  -f="tcp": BPF filter for pcap
  -filter_bool=true: Bool operator to use CIDR filter against
  -filter_dst=false: Filter packets by their destination
  -filter_ip_CIDR="0.0.0.0/0": CIDR Mask to allow traffic
  -filter_src=false: Filter packets by their source
  -i="eth0": Interface to get packets from
  -l="": incoming log dir used initially for pcap files if packet logging is enabled
  -log_packets=false: if set to true then log all packets for each tracked TCP connection
  -loglevel="info": LogLevel: 'debug', 'info', 'warn', 'error', 'fatal', 'panic'?
  -max_pcap_log_size=1: maximum pcap size per rotation in megabytes
  -max_pcap_rotations=10: maximum number of pcap rotations per connection
  -pcapfile="": pcap filename to read packets from rather than a wire interface.
  -s=65536: SnapLen for pcap packet capture
  -slack_channel="#wherefore": Slack Channel to send messages to
  -slack_emoji=":warning:": Emoji icon to use for icon instead of URL
  -slack_icon="https://cdn4.iconfinder.com/data/icons/proglyphs-free/512/Invader_1-128.png": Icon URL for slack message
  -slack_url="nil": Slack Hook URL
  -transfer_interval="5s": Interval in seconds to meansure network flow transfer
  -w="3s": timeout for reading packets off the wire
```

### System Dependencies

Debian libpcap dependencies:

Install the following via apt:

* `libpcap-dev`
* `libpcap2-bin`

## Building

Compiled with Golang 1.4+

It is not a good idea to run network traffic analysis tools as root. In Linux you can run these tools as an unprivileged user after you run setcap as root like this:
```
godep go build -a -v && sudo setcap cap_net_raw,cap_net_admin=eip wherefore
```

## Running

Configuration will depend on your use case and tolerences desired. Below are some possible use cases which will hopefully be a good starting point for operation.

```
./wherefore -i eth0 -l=/var/log/wherefore -archive_dir=/var/log/wherefore/packets/ \
    -loglevel=info \
    -slack_url="https://hooks.slack.com/services/your/integration/keys/here" -slack_channel="#wherefore" -slack_emoji=":warning:" \
    -anom_methods=fence -anom_upper_bound=1000 -anom_gv_cap=25 -anom_sensitivity=0.8
```

Alert on almost all connections due to the extremely low upper bound threshold.
```
./wherefore -i eth0 -l=/tmp -archive_dir=/tmp  -loglevel=info -anom_methods=diff,fence -anom_upper_bound=200 -slack_url="https://hooks.slack.com/services/hook/url/goes/here" -slack_channel="#wherefore" -slack_emoji=":warning:" -anom_gv_cap=30 -anom_sensitivity=0.8 
```

