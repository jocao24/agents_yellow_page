import Pyro4
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


if __name__ == '__main__':
    print("Starting yellow_page...")
    ip_name_server = request_ipns()
    ManageDataYellowPage().save_data_yp(ip_name_server)
    nameserver = Pyro4.locateNS(host=ip_name_server, port=9090)
    print("Nameserver localized: ", nameserver)
    server_daemon = Pyro4.Daemon(host=ip_local)
    print("Instantiating the Yellow Page...")
    server_yellow_page = YellowPage(nameserver)
    print("Yellow page object instantiated correctly")
    server_uri = server_daemon.register(server_yellow_page)
    name_yellow_page = 'yellow_page@' + ip_local
    nameserver.register(name_yellow_page, server_uri)
    print("Yellow page yellow_page registered with URI: ", server_uri)
    server_daemon.requestLoop()
