import logging
import os
import socket
import multiprocessing
import subprocess
import re
import csv
import json
from urllib.request import urlopen
from datetime import datetime, date


def pinger(job_q, results_q):
    """
    Do Ping
    :param job_q:
    :param results_q:
    :return:
    """
    DEVNULL = open(os.devnull, 'w')
    while True:

        ip = job_q.get()

        if ip is None:
            break

        try:
            subprocess.check_call(['ping', '-c1', ip],
                                  stdout=DEVNULL)
            results_q.put(ip)
        except:
            pass


def get_my_ip():
    """
    Find my IP address
    :return:
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    print("This is my IP : " + ip)
    s.close()
    return ip


def map_network(pool_size=255):
    """
    Maps the network
    :param pool_size: amount of parallel ping processes
    :return: list of valid ip addresses
    """

    ip_list = list()

    # get my IP and compose a base like 192.168.1.xxx
    ip_parts = get_my_ip().split('.')
    base_ip = ip_parts[0] + '.' + ip_parts[1] + '.' + ip_parts[2] + '.'

    # prepare the jobs queue
    jobs = multiprocessing.Queue()
    results = multiprocessing.Queue()

    pool = [multiprocessing.Process(target=pinger, args=(jobs, results)) for i in range(pool_size)]

    for p in pool:
        p.start()

    # cue hte ping processes
    for i in range(1, 255):
        jobs.put(base_ip + '{0}'.format(i))

    for p in pool:
        jobs.put(None)

    for p in pool:
        p.join()

    # collect he results
    while not results.empty():
        ip = results.get()
        ip_list.append(ip)

    return ip_list


def get_mac_from_own(interface):
    try:
        mac = open('/sys/class/net/' + interface + '/address').readline()
    except:
        mac = "00:00:00:00:00:00"
    return mac[0:17]


def get_mac_address(ip_address, interface):
    pid = subprocess.Popen(["arp", "-n", ip_address], stdout=subprocess.PIPE)
    s = pid.communicate()[0].decode('utf-8')
    regex = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s)
    if regex is not None:
        mac = regex.groups()[0]
        print(mac)
    else:
        mac = get_mac_from_own(interface)
    return mac


def get_hostname(ip_address):
    return socket.gethostbyaddr(ip_address)[0]


def write_devices_to_json(devices):
    with open(path_to_json, 'w') as network_json:
        network_json.write(json.dumps(devices))


def get_old_devices_from_json():
    with open(path_to_json, 'r') as network_json:
        devices = json.load(network_json)
        return devices


def get_full_device_list(new_devices, passed_devices):
    final_device_list = []
    if len(passed_devices) > 0:
        for passed_device in passed_devices:
            is_found = False
            for new_device in new_devices:
                if passed_device['mac_address'] == new_device['mac_address']:
                    is_found = True
                    final_device_list.append(new_device)

            if not is_found:
                passed_device['connected'] = "false"
                final_device_list.append(passed_device)
    else:
        final_device_list = new_devices

    return final_device_list


def check_if_files_exist():
    # Check if data folder exists
    if not os.path.exists(path_to_data_folder):
        os.mkdir(path_to_data_folder)
    # Check if json exists first
    if not os.path.exists(path_to_json):
        with open(path_to_json, 'w') as network_json:
            network_json.write(json.dumps([]))

    # Check if csv exists then
    if not os.path.exists(path_to_csv):
        with open(path_to_csv, 'w') as admin:
            fields = ["Hostname", "Adresse MAC", "Adresse IP", "Date/Heure", "Date", "Time"]
            w = csv.DictWriter(admin, delimiter=",", fieldnames=fields)
            w.writeheader()


def create_folder_and_files_device(device):
    path = device['path']
    if not os.path.exists(path):
        os.mkdir(path)
        with open(path + path_to_last_ping, "w") as file:
            pass
        with open(path + path_to_ping, "w") as file:
            fields = ["Hostname", "Adresse MAC", "Adresse IP", "Date/Heure", "Date", "Time"]
            w = csv.DictWriter(file, delimiter=",", fieldnames=fields)
            w.writeheader()

    if not os.path.exists(path + path_to_last_ping):
        with open(path + path_to_last_ping, "w") as file:
            pass

    if not os.path.exists(path + path_to_ping):
        with open(path + path_to_ping, "w") as file:
            fields = ["Hostname", "Adresse MAC", "Adresse IP", "Date/Heure", "Date", "Time"]
            w = csv.DictWriter(file, delimiter=",", fieldnames=fields)
            w.writeheader()

    if not os.path.exists(path_to_log_folder):
        os.mkdir(path_to_log_folder)
    if not os.path.exists(path_to_error_url):
        with open(path_to_error_url, "w") as file:
            pass
    if not os.path.exists(path_to_list_ip):
        with open(path_to_list_ip, "w") as file:
            pass


def append_device_data_to_files(device):
    path = device['path']
    with open(path + path_to_last_ping, "w") as file:
        file.write(device['datetime'])

    with open(path + path_to_ping) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        fieldnames = csv_reader
        for row in csv_reader:
            fieldnames = row
            break

    with open(path + path_to_ping, "a") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writerow({fieldnames[0]: device["hostname"], fieldnames[1]: device["mac_address"],
                         fieldnames[2]: device["ip_address"], fieldnames[3]: device["datetime"],
                         fieldnames[4]: device["date"], fieldnames[5]: device["time"]})


def append_device_data_to_global_csv(device):
    with open(path_to_csv) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        fieldnames = csv_reader
        for row in csv_reader:
            fieldnames = row
            break

    with open(path_to_csv, 'a') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writerow({fieldnames[0]: device["hostname"], fieldnames[1]: device["mac_address"],
                         fieldnames[2]: device["ip_address"], fieldnames[3]: device["datetime"],
                         fieldnames[4]: device["date"], fieldnames[5]: device["time"]})


def url_is_reachable(url):
    try:
        response = urlopen(url, timeout=4).read().decode('utf-8')
    except:
        return False
    return response.getcode() == 200


def test_pages():
    with open(path_to_list_ip) as file:
        valid_urls = []
        for line in file:
            line_list = line.split('-')
            vm_name = line_list[0]
            vm_url = line_list[1].strip('\n')
            if not url_is_reachable(vm_url):
                with open(path_to_error_url, 'a') as error_file:
                    error_line = vm_name + "-" + vm_url + "-" + datetime.now().strftime("%d/%m/%Y %H:%M:%S") + '\n'
                    error_file.write(error_line)
            else:
                valid_urls.append(vm_name + "-" + vm_url + "-" + datetime.now().strftime("%d/%m/%Y %H:%M:%S") + '\n')
        if len(valid_urls) > 0:
            with open(path_to_success_url, "w") as success_file:
                for url in valid_urls:
                    success_file.write(url)


def launch_script():
    print('Mapping and pinging network...')
    list_ips = map_network()

    # Check if data files exist, if they dont we need create them
    check_if_files_exist()

    list_devices = []
    today = date.today()
    now = datetime.now()

    for ip in list_ips:
        mac = get_mac_address(ip, network_interface)
        # hostname = get_hostname(ip)
        hostname = "Inconnue"
        device = {
            "hostname": hostname,
            "ip_address": ip,
            "mac_address": mac,
            "datetime": now.strftime("%d/%m/%Y %H:%M:%S"),
            "date": today.strftime("%d/%m/%Y"),
            "time": now.strftime("%H:%M:%S"),
            "connected": "true",
            "path": path_to_data_folder + mac.replace(":", "-")
        }
        list_devices.append(device)

        # Check if data folder for this device exists, create it if it dont
        create_folder_and_files_device(device)
        # Append data to files
        append_device_data_to_files(device)

        # Append data to global csv data file
        # append_device_data_to_global_csv(device) ## Uncomment line to append data to the big csv data file

    old_devices = get_old_devices_from_json()
    full_device_list = get_full_device_list(list_devices, old_devices)
    print(full_device_list)
    write_devices_to_json(full_device_list)

    print('Testing VMs and websites...')
    test_pages()


if __name__ == '__main__':
    path_to_data_folder = "data/"
    path_to_log_folder = path_to_data_folder + "logs/"
    path_to_json = path_to_data_folder + "network.json"
    path_to_csv = path_to_data_folder + "admin.csv"
    path_to_list_ip = path_to_data_folder + "list-ips.txt"
    path_to_error_url = path_to_log_folder + "error-url.txt"
    path_to_success_url = path_to_log_folder + "success-url.txt"

    path_to_last_ping = "/last_ping.txt"
    path_to_ping = "/ping.csv"
    network_interface = "enp0s3"

    launch_script()
