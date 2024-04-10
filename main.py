import sys
import threading
import Pyro4
from src.manage_data import start_new_session_log, log_message, get_end_session_log, get_all_agents_registered
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
    s.settimeout(2)  # Timeout después de 2 segundos
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


def daemon_loop():
    daemon.requestLoop()


def check_finally_event():
    finally_yp.wait()
    log_message("Yellow Page Finally. Shutting down...")
    daemon.shutdown()
    sys.exit(0)


if __name__ == '__main__':
    start_new_session_log()
    data_management_instance = DataManagement()
    current_data = data_management_instance.load()
    finally_yp = threading.Event()
    ip_name_server = request_ipns(current_data['data_ultimate_connection']['ip_ultimate_ns'])
    current_data['data_ultimate_connection']['ip_ultimate_ns'] = ip_name_server
    data_management_instance.save(current_data)
    log_message(f"IP of the nameserver: {ip_name_server}")
    nameserver = Pyro4.locateNS(host=ip_name_server, port=9090)
    log_message(f"Nameserver located in: {ip_name_server}:9090")
    daemon = Pyro4.Daemon(host=ip_local)
    server_yellow_page = YellowPage(nameserver, ip_name_server)
    server_uri = daemon.register(server_yellow_page)
    name_yellow_page = 'yellow_page@' + ip_local
    nameserver.register(name_yellow_page, server_uri)
    server_yellow_page.server_uri = server_uri
    log_message(f"Yellow Page registered with URI: {server_uri}")
    log_message("Yellow Page running...")
    daemon_thread = threading.Thread(target=daemon_loop)
    daemon_thread.start()

    check_finally_yp = threading.Thread(target=check_finally_event)
    check_finally_yp.start()

    while True:
        print("1. View logs")
        print("2. View all agents registered")
        print("3. View Shared Key for register gateway")
        print("4. Exit")
        option = input("Enter the number of the option you want to execute: ")
        if option == '1':
            logs = get_end_session_log()
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
            nameserver.remove(name_yellow_page, server_uri)
            finally_yp.set()
            exit()
        else:
            print("Invalid option. Please enter a valid option.")
