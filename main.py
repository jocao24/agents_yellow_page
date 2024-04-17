import os
import sys
import threading
import Pyro5.core
import Pyro5.errors
import Pyro5.nameserver
import Pyro5.api
from src.manage_data import get_all_agents_registered
from src.manage_logs import ManagementLogs
from src.security.data_management import DataManagement
from src.utils.print_logs import print_agents
from src.yellow_page_remote_object import YellowPage
from src.utils.get_ip import get_ip
import socket

from src.utils.validate_ip import validate_ip

ip_local = get_ip()


def request_ip() -> str:
    while True:
        ip_ns = input("Enter the IP of the nameserver. If it is the same as the NameServer, press enter: ")
        if ip_ns:
            is_valid_ip = validate_ip(ip_ns)
            if not is_valid_ip:
                print("The IP entered is not valid. Please enter a valid IP.")
                continue
            break
        ip_ns = get_ip()
        break
    return ip_ns


def is_ip_active(ip: str, port: int = 9090) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect((ip, port))
        s.close()
        return True
    except socket.error:
        return False


def request_ipns(ip_ns_saved):
    ip_ns = None
    while True:
        opt_select = 'n'
        if ip_ns_saved:
            opt_select = input(f"Do you want to use the NS IP '{ip_ns_saved}' saved? (y/n) default: n: ")
        if opt_select.lower() == 'y':
            if validate_ip(ip_ns_saved):
                if is_ip_active(ip_ns_saved):
                    ip_ns = ip_ns_saved
                    break
                else:
                    print(f"The nameserver at {ip_ns_saved} is not active. Please enter a valid IP.")
            if not ip_ns:
                print("The IP of the ns saved is not valid or not active. Please enter a valid IP.")
                ip_ns = request_ip()
            break
        elif opt_select.lower() == 'n':
            ip_ns = request_ip()
            break
        else:
            print("Invalid option. Please enter a valid option.")
    return ip_ns


def daemon_loop(daemon):
    try:
        daemon.requestLoop()
    except KeyboardInterrupt:
        pass



def check_finally_event(finally_yp, daemon, management_logs):
    finally_yp.wait()
    daemon.shutdown()  # Ensure the daemon is shut down cleanly
    management_logs.log_message("Yellow Page Finally. Shutting down...")
    sys.exit(0)  # Normal exit


if __name__ == '__main__':
    data_management_instance = DataManagement()
    management_logs = ManagementLogs(data_management_instance)
    management_logs.start_new_session_log()
    current_data = data_management_instance.load()
    finally_yp = threading.Event()
    ip_name_server = request_ipns(current_data['data_ultimate_connection']['ip_ultimate_ns'])
    current_data['data_ultimate_connection']['ip_ultimate_ns'] = ip_name_server
    data_management_instance.save(current_data)
    management_logs.log_message(f"IP of the nameserver: {ip_name_server}")
    nameserver = Pyro5.core.locate_ns(host=ip_name_server, port=9090)
    management_logs.log_message(f"Nameserver located in: {ip_name_server}:9090")
    daemon = Pyro5.api.Daemon(host=ip_local)
    server_yellow_page = YellowPage(nameserver, ip_name_server, management_logs)
    server_uri = daemon.register(server_yellow_page)
    name_yellow_page = 'yellow_page' + ip_local
    nameserver.register(name_yellow_page, server_uri, metadata={name_yellow_page})
    server_yellow_page.server_uri = server_uri
    management_logs.log_message(f"Yellow Page registered with URI: {server_uri}")
    management_logs.log_message("Yellow Page running...")
    daemon_thread = threading.Thread(target=daemon_loop, args=(daemon,))
    daemon_thread.daemon = True
    daemon_thread.start()

    check_finally_thread = threading.Thread(target=check_finally_event, args=(finally_yp, daemon, management_logs))
    check_finally_thread.daemon = True
    check_finally_thread.start()

    while True:
        print("1. View logs")
        print("2. View all agents registered")
        print("3. View Shared Key for register gateway")
        print("4. Exit")
        option = input("Enter the number of the option you want to execute: ")
        if option == '1':
            logs = management_logs.get_end_session_log()
            print("===============================================================")
            print(logs)
            print("===============================================================")
        elif option == '2':
            agents_registered = get_all_agents_registered()
            print(
                "==============================================================================================================================")
            print_agents(agents_registered)
            print(
                "==============================================================================================================================")
        elif option == '3':
            shared_key = server_yellow_page.shared_key
            print(f"The shared key is: {shared_key}")
            print("The shared key has been generated. Please enter the shared key in the gateway.")

        elif option == '4':
            finally_yp.set()
            break
        else:
            print("Invalid option. Please enter a valid option.")

    daemon_thread.join()
    check_finally_thread.join()
    print("Exiting...")
    os._exit(0)
