import ipaddress
import csv
import pickle
import os.path

from collections import defaultdict
from tqdm import tqdm

IP_COUNT_KEY = "ip_count"
MIN_SUBNET_PREFIX = 16


def split_range(start_ip, end_ip):
    subnets = list(
        ipaddress.summarize_address_range(
            ipaddress.IPv4Address(start_ip.strip()),
            ipaddress.IPv4Address(end_ip.strip()),
        )  # returns a generator of cidr subnets
    )
    result = []
    for net in subnets:
        if net.prefixlen < MIN_SUBNET_PREFIX:
            result.extend(net.subnets(new_prefix=MIN_SUBNET_PREFIX))
        else:
            result.append(net)
    return result


def load_networks(filename):

    # try to load using pickle
    pickle_filename = filename + ".pickle"
    if os.path.isfile(pickle_filename):
        print(f"{pickle_filename} found, loading...")
        with open(pickle_filename, "rb") as file:
            from timeit import default_timer as timer

            start = timer()
            data = pickle.load(file)
            end = timer()
            print(
                f"Loaded {len(data)} networks from pickle dump in {end-start:.2f} seconds."
            )
            return data

    data = defaultdict(dict)
    file = open(filename, "r", encoding="iso-8859-1")
    lines = file.readlines()

    current_range = None
    prev_key = None
    for line in tqdm(lines, desc="Loading networks", unit="row"):
        if line.startswith("#"):
            continue
        if not line.strip():
            current_range = None
            continue
        key = line.split(":")[0].strip()
        if key not in ("inetnum", "netname", "country", "descr"):
            continue
        value = line.split(":")[1].strip()
        if key == "descr" and prev_key == "descr":
            # only keep first descr
            continue

        if key == "inetnum":
            start_ip, end_ip = value.split("-")
            current_range = split_range(start_ip.strip(), end_ip.strip())
            num_addr = sum(net.num_addresses for net in current_range)
            # keep only the most specific subnet in case they overlap
            current_range = [
                cidr
                for cidr in current_range
                if not (cidr in data and data[cidr]["num_addr_orig"] < num_addr)
            ]
            for cidr in current_range:
                data[cidr]["cidr"] = str(cidr)
                data[cidr]["num_addr_orig"] = num_addr

        for cidr in current_range:
            data[cidr][key] = value

        prev_key = key

    # remove generic blocks
    data = dict(
        (k, v)
        for (k, v) in data.items()
        if v["netname"]
        not in ("IANA-BLOCK", "ARIN-CIDR-BLOCK", "RIPE-CIDR-BLOCK", "ERX-NETBLOCK")
        and not v["netname"].startswith("IANA-NETBLOCK")
        and not v["netname"].startswith("STUB-")
        and not v["country"] == "ZZ"
    )

    print(f"Loaded {len(data)} networks")
    # store to pickle
    with open(filename + ".pickle", "wb") as file:
        pickle.dump(data, file)
    return data


def guess_subnets(ip):
    # Try mask lengths from 31 down to 7
    for mask_length in range(31, 6, -1):
        yield ipaddress.IPv4Network(f"{ip}/{mask_length}", strict=False)


def count_ips(filename, networks):
    file = open(filename, "r")
    lines = file.readlines()
    for ip in tqdm(lines, desc="Processing", unit="ip"):
        ip = ip.strip()

        found = False
        for subnet in guess_subnets(ip):
            if subnet in networks:
                obj = networks[subnet]
                obj[IP_COUNT_KEY] = obj.get(IP_COUNT_KEY, 0) + 1
                found = True
                if obj["netname"] == "APNIC-AP":
                    print(f"Found APNIC-AP {obj['cidr']} for {ip=}")
                break
        # if not found:
        #     print(f"No subnet found for {ip=}")


if __name__ == "__main__":
    inetnum_file = ".data/apnic.db.inetnum"
    # inetnum_file = ".data/apnic_test.txt"
    networks = load_networks(inetnum_file)

    # ip_file = ".data/ip_test.txt"
    ip_file = ".data/ips.txt"
    count_ips(ip_file, networks)

    my_subnets = [
        networks[net] for net in networks if networks[net].get(IP_COUNT_KEY, 0)
    ]
    my_subnets.sort(key=lambda x: x[IP_COUNT_KEY], reverse=True)

    header = [
        "ip_count",
        "cidr",
        "country",
        "netname",
        "descr",
        "inetnum",
        "num_addr_orig",
    ]
    with open("results.csv", "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(header)
        for net in my_subnets:
            writer.writerow([net[key] for key in header])
