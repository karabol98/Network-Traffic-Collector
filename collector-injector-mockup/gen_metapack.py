#!/usr/bin/env python3
import random
import datetime
import uuid
from ipaddress import IPv4Address
import pyarrow as pa
from msgspec import msgpack


def random_ip(network_prefix=None):
    """Generate random IP address, optionally from a specific network"""
    if network_prefix == "192.168.1":
        return f"192.168.1.{random.randint(1, 254)}"
    elif network_prefix == "203.0.113":
        return f"203.0.113.{random.randint(1, 254)}"
    else:
        return str(IPv4Address(random.getrandbits(32)))

def generate_traffic_log(timestamp : datetime.datetime, logtype="notice"):
    """Generate a Fortigate traffic log"""

    # Common attributes for all logs
    devname = "FortiGate-500E"
    devid = "FG5H0E0000000000"
    tz = "-0100"

    # Random attributes
    src_internal = random.choice([True, True, True, False])  # 75% chance of internal source

    if src_internal:
        srcip = random_ip("192.168.1")
        srcintf = "port1"
        srcintfrole = "lan"
        srccountry = "Reserved"
        dstintf = "wan1"
        dstintfrole = "wan"
        trandisp = "snat"
        transip = "203.0.113.2"
    else:
        srcip = random_ip()
        srcintf = "wan1"
        srcintfrole = "wan"
        srccountry = random.choice(["United States", "Canada", "Germany", "France", "China", "Japan"])
        dstintf = "port1"
        dstintfrole = "lan"
        trandisp = "dnat"
        transip = random_ip("192.168.1")

    srcport = random.randint(10000, 65000)

    # Destination details
    dstip = random_ip() if src_internal else random_ip("192.168.1")
    dstcountry = random.choice(["United States", "Germany", "Netherlands", "France"]) if src_internal else "Reserved"

    # Service details
    service_options = {
        "HTTP": {"port": 80, "proto": 6, "appcat": "Web.Client"},
        "HTTPS": {"port": 443, "proto": 6, "appcat": "Web.Client"},
        "DNS": {"port": 53, "proto": 17, "appcat": "Network.Service"},
        "SMTP": {"port": 25, "proto": 6, "appcat": "Email"},
        "SSH": {"port": 22, "proto": 6, "appcat": "Network.Service"},
        "FTP": {"port": 21, "proto": 6, "appcat": "File.Transfer"}
    }

    service = random.choice(list(service_options.keys()))
    dstport = service_options[service]["port"]
    proto = service_options[service]["proto"]
    appcat = service_options[service]["appcat"]

    # Action and policy details
    action = random.choice(["close", "accept", "deny"]) if logtype == "notice" else "deny"
    policyid = random.randint(1, 5)
    policytype = "policy"

    # Connection details
    transport = srcport
    duration = random.randint(0, 200) if action != "deny" else 0
    sentbyte = random.randint(1000, 50000) if action != "deny" else 0
    rcvdbyte = random.randint(1000, 150000) if action != "deny" else 0
    sentpkt = random.randint(10, 200) if action != "deny" else 0
    rcvdpkt = random.randint(10, 150) if action != "deny" else 0
    sessionid = random.randint(10000, 99999)

    # Build the log
    logid = "0000000013" if action != "deny" else "0000000014"
    poluuid = str(uuid.uuid4())
    unix_timestamp = timestamp.timestamp()
    
    log = {
        "_time": unix_timestamp,
        "date": timestamp.strftime('%Y-%m-%d'),
        "time": timestamp.strftime('%H:%M:%S'),
        "devname": devname,
        "devid": devid,
        "eventtime": int(timestamp.timestamp()),
        "tz": tz,
        "logid": logid,
        "type": "traffic",
        "subtype": "forward",
        "level": logtype,
        "vd": "root",
        "srcip": srcip,
        "srcport": srcport,
        "srcintf": srcintf,
        "srcintfrole": srcintfrole,
        "dstip": dstip,
        "dstport": dstport,
        "dstintf": dstintf,
        "dstintfrole": dstintfrole,
        "poluuid": poluuid,
        "sessionid": sessionid,
        "proto": proto,
        "action": action,
        "policyid": policyid,
        "policytype": policytype,
        "service": service,
        "dstcountry": dstcountry,
        "srccountry": srccountry,
        "trandisp": trandisp,
        "transip": transip,
        "transport": transport,
        "duration": duration,
        "sentbyte": sentbyte,
        "rcvdbyte": rcvdbyte,
        "sentpkt": sentpkt,
        "rcvdpkt": rcvdpkt,
        "appcat": appcat
    }

    return log

def generate_event_log(timestamp : datetime.datetime, event_type="admin_login"):
    """Generate a Fortigate event log"""
    devname = "FortiGate-500E"
    devid = "FG5H0E0000000000"
    tz = "-0700"
    unix_timestamp = timestamp.timestamp()

    if event_type == "admin_login":
        logid = "0100040704"
        subtype = "system"
        level = "notice"
        logdesc = "Admin login successful"
        user = "admin"
        ui = "ssh(203.0.113.10)"
        method = "ssh"
        srcip = "203.0.113.10"
        dstip = "203.0.113.2"
        action = "login"
        status = "success"
        reason = "none"
        profile = "super_admin"
        msg = f"Administrator admin logged in successfully from ssh({srcip})"

        log = {
            "_time": unix_timestamp,
            "date": timestamp.strftime('%Y-%m-%d'),
            "time": timestamp.strftime('%H:%M:%S'),
            "devname": devname,
            "devid": devid,
            "eventtime": int(timestamp.timestamp()),
            "tz": tz,
            "logid": logid,
            "type": "event",
            "subtype": subtype,
            "level": level,
            "vd": "root",
            "logdesc": logdesc,
            "user": user,
            "ui": ui,
            "method": method,
            "srcip": srcip,
            "dstip": dstip,
            "action": action,
            "status": status,
            "reason": reason,
            "profile": profile,
            "msg": msg
        }
    else:  # system performance
        logid = "0100044546"
        subtype = "system"
        level = "alert"
        logdesc = "System performance statistics"
        cpu = random.randint(5, 50)
        memory = random.randint(20, 70)
        disk = random.randint(15, 85)
        session_rate = random.randint(5, 50)
        virus_events = random.randint(0, 5)
        ips_events = random.randint(0, 10)

        msg = f"CPU: {cpu}%, Memory: {memory}%, Disk: {disk}%, Average session setup rate: {session_rate}/sec, Virus events: {virus_events}/hr, IPS events: {ips_events}/hr"
        log = {
            "_time": unix_timestamp,
            "date": timestamp.strftime('%Y-%m-%d'),
            "time": timestamp.strftime('%H:%M:%S'),
            "devname": devname,
            "devid": devid,
            "eventtime": int(timestamp.timestamp()),
            "tz": tz,
            "logid": logid,
            "type": "event",
            "subtype": subtype,
            "level": level,
            "vd": "root",
            "logdesc": logdesc,
            "msg": msg
        }

    return log

def generate_logs(num_logs=10, start_time:datetime.datetime=None, interval_minutes=0):
    """Generate a series of Fortigate logs"""
    logs = []

    if start_time is None:
        start_time = datetime.datetime.now()

    current_time = start_time
    started_at = datetime.datetime.now()

    for i in range(num_logs):
        # 85% chance for traffic log, 15% chance for event log
        log_type = random.choices(["traffic", "event"], weights=[85, 15])[0]

        if log_type == "traffic":
            # 10% chance for warning level log (deny)
            level = random.choices(["notice", "warning"], weights=[90, 10])[0]
            logs.append(generate_traffic_log(current_time, level))
        else:
            # 70% chance for admin login, 30% chance for system performance
            event_type = random.choices(["admin_login", "system_perf"], weights=[70, 30])[0]
            logs.append(generate_event_log(current_time, event_type))

        # Increment time for next log
        minutes_offset = random.randint(0, interval_minutes)
        seconds_offset = random.randint(0, 59)
        current_time += datetime.timedelta(minutes=minutes_offset, seconds=seconds_offset)

        # Print progress every 100,000 events
        if (i + 1) % 100000 == 0:
            # Calculate and print elapsed time since start
            elapsed = datetime.datetime.now() - started_at
            # Calculate remaining events and ETA
            remaining = num_logs - (i + 1)
            processed_per_second = (i + 1) / elapsed.total_seconds() if elapsed.total_seconds() > 0 else 0
            if processed_per_second > 0:
                eta_seconds = remaining / processed_per_second
                eta = datetime.timedelta(seconds=int(eta_seconds))
                print(f"{i + 1} Elapsed time: {elapsed} Remaining: {remaining} logs, ETA: {eta}")

    return logs

def main():
    # Start time for logs (default to yesterday)
    start_time = datetime.datetime.now() - datetime.timedelta(days=1)
    start_time = start_time.replace(hour=8, minute=0, second=0, microsecond=0)

    # Generate 50 logs with interval between 1-5 minutes
    logs = generate_logs(1000000, start_time)
    filename="forti.log"


    table = pa.Table.from_pylist(logs)

    events = [table[col_name].to_pylist() for col_name in table.column_names]
    columns = table.column_names
    metapack = {
         "header":{
            "timeformat": "unixms",
            "timefield": "_time",
            "index": "main",
            "format": "metapack"
        },
        "columns": columns,
        "events": events
    }

    bs = msgpack.Encoder().encode(metapack)

    with open("forti.msgpack", "wb") as f:
        f.write(bs)

    print(f"Generated {len(logs)} test logs in {filename}")

if __name__ == "__main__":
    main()
