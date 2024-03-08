import sys
import threading

import Pyro4

from manage_logs.manage_logs import start_new_session_log, log_message, get_end_session_log
from utils.validate_ip import validate_ip
from domain.class_for_yp.manage_data_yp import ManageDataYellowPage
from domain.models.yellow_page import YellowPage
from utils.get_ip import get_ip

ip_local = get_ip()


def request_ip() -> str:
    request_ip = True
    while request_ip:
        ip_yp = input("Enter the IP of the nameserver. If it is the same as the NameServer, press enter: ")
        if ip_yp:
            is_valid_ip = validate_ip(ip_yp)
            if not is_valid_ip:
                print("The IP entered is not valid. Please enter a valid IP.")
                continue
            break
        ip_yp = get_ip()
        break
    return ip_yp


def request_ipns():
    ip_ns = None
    while True:
        is_valid_ip = False
        opt_select = input("Do you want to use the nameserver IP saved in the configuration file? (y/n): ")
        if opt_select.lower() == 'y':
            ip_yp = ManageDataYellowPage().get_data_yp()
            if ip_yp:
                is_valid_ip = validate_ip(ip_yp)
            if not is_valid_ip or not ip_yp:
                print("The IP of the ns saved in the configuration file is not valid. Please enter a valid IP.")
                ip_yp = request_ip()
            break
        elif opt_select.lower() == 'n':
            ip_yp = request_ip()
            break
        else:
            print("Invalid option. Please enter a valid option.")
    return ip_yp


def daemon_loop():
    daemon.requestLoop()


def check_finally_event():
    finally_yp.wait()
    log_message("Yellow Page Finally. Shutting down...")
    daemon.shutdown()
    sys.exit(0)


if __name__ == '__main__':
    start_new_session_log()
    finally_yp = threading.Event()
    ip_name_server = request_ipns()
    ManageDataYellowPage().save_data_yp(ip_name_server)
    log_message(f"IP of the nameserver: {ip_name_server}")
    nameserver = Pyro4.locateNS(host=ip_name_server, port=9090)
    log_message(f"Nameserver located in: {ip_name_server}:9090")
    daemon = Pyro4.Daemon(host=ip_local)
    server_yellow_page = YellowPage(nameserver)
    server_uri = daemon.register(server_yellow_page)
    name_yellow_page = 'yellow_page@' + ip_local
    nameserver.register(name_yellow_page, server_uri)
    log_message(f"Yellow Page registered with URI: {server_uri}")
    log_message("Yellow Page running...")
    daemon_thread = threading.Thread(target=daemon_loop)
    daemon_thread.start()

    check_finally_yp = threading.Thread(target=check_finally_event)
    check_finally_yp.start()

    while True:
        print("1. View logs")
        print("2. Exit")
        option = input("Enter the number of the option you want to execute: ")
        if option == '1':
            logs = get_end_session_log()
            print("===============================================================")
            print(logs)
            print("===============================================================")
        elif option == '2':
            finally_yp.set()
            exit()
        else:
            print("Invalid option. Please enter a valid option.")


