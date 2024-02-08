import requests
from pysnmp.hlapi import *
import urllib3

urllib3.disable_warnings()
api_url = "https://192.168.99.10/api"
api_token = "2f5294f72819946284d36e7bccb42380cfd9ca92"
headers = {
    "Authorization": f"Token {api_token}",
    "Content-Type": "application/json"
}
role_to_filter = "switch"

auth_user = "botUser"
auth_protocol = usmHMACSHAAuthProtocol
auth_password = "j4p3UbaWEveVWz2omitn"
priv_protocol = usmAesCfb128Protocol
priv_password = "Q2yJk7uuSz9iqVhEoxyz"

priv_password_Aruba = "c5ecae92ae2bd3c253c2"
priv_protocol_Aruba = usmDESPrivProtocol

oid_ports = "1.3.6.1.2.1.17.7.1.4.5.1.1"
oid_vlan_info = "1.3.6.1.2.1.17.7.1.4.3.1.2"
port_membership_oid = "1.3.6.1.2.1.17.7.1.4.3.1.2"


def get_vlan_list(ip_address, auth_user, auth_protocol, auth_password, priv_protocol, priv_password, oid):
    user = UsmUserData(
        auth_user,
        auth_password,
        priv_password,
        auth_protocol,
        priv_protocol
    )
    transport_target = UdpTransportTarget((ip_address, 161))

    vlan_ids = []  # Lista do przechowywania numerów VLAN

    for (error_indication, error_status, error_index, var_binds) in nextCmd(
            SnmpEngine(),
            user,
            transport_target,
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False
    ):
        if error_indication:
            print(f"Error: {error_indication}")
            return None  # Zwróć None w przypadku błędu
        elif error_status:
            print(f"Error: {error_status}")
            return None  # Zwróć None w przypadku błędu
        else:
            for var_bind in var_binds:
                oid_str = var_bind[0].prettyPrint()  # Pobierz identyfikator obiektu SNMP jako string
                vlan_num = oid_str.split(".")[-1]  # Wyodrębnij numer VLAN z końca identyfikatora obiektu
                vlan_ids.append(int(vlan_num))  # Dodaj numer VLAN do listy jako liczbę całkowitą

    return vlan_ids  # Zwróć listę numerów VLAN


def get_vlan_and_port_info(ip_address, auth_user, auth_protocol, auth_password, priv_protocol, priv_password, vlan_ids,
                           port_membership_oid):
    user = UsmUserData(
        auth_user,
        auth_password,
        priv_password,
        auth_protocol,
        priv_protocol
    )

    if not vlan_ids:
        print("Lista numerów VLAN jest pusta. Zakończono działanie programu.")
        return

    for vlan_id in vlan_ids:
        port_membership_oid_base = f"{port_membership_oid}.{vlan_id}"

        port_list = []  # Lista portów przypisanych do danego VLAN-u

        for (error_indication, error_status, error_index, var_binds) in getCmd(
                SnmpEngine(),
                user,
                UdpTransportTarget((ip_address, 161)),
                ContextData(),
                ObjectType(ObjectIdentity(port_membership_oid_base)),
                lexicographicMode=False
        ):
            if error_indication:
                print(f"Error: {error_indication}")
            elif error_status:
                print(f"Error: {error_status}")
            else:
                for var_bind in var_binds:
                    port_info = var_bind[1].prettyPrint()  # Pobierz informacje o przypisanych portach jako string
                    print_port_info(port_info, vlan_id, ip_address, auth_user, auth_protocol, auth_password, priv_protocol,
                    priv_password)

def print_port_info(port_info, vlan_id, ip_address, auth_user, auth_protocol, auth_password, priv_protocol, priv_password):
    hex_string = port_info.split(':')[-1].strip()  # Remove header and spaces, leaving only the hexadecimal value
    bin_string = bin(int(hex_string, 16))[2:]  # Convert hexadecimal value to binary, skip the '0b' prefix

    # Pad with missing zeros to complete the 64-bit binary string
    bin_string = bin_string.zfill(64)

    port_list = []

    # Interpret each bit in the binary string
    for i in range(len(bin_string)):
        if bin_string[i] == '1':
            port_list.append(i + 1)  # Add port number (starting from 1)

    # Print port information excluding ports with names containing "po1" to "po8"
    if port_list:
        print(f"VLAN VID {vlan_id}: ", end="")
        for port in port_list:
            port_name = get_port_name(ip_address, auth_user, auth_protocol, auth_password, priv_protocol, priv_password, port)
            print(f"Port {port} ({port_name})", end=", ")
        print()  # New line



def get_port_name(ip_address, auth_user, auth_protocol, auth_password, priv_protocol, priv_password, port_number):
    port_name_oid_base = "1.3.6.1.2.1.31.1.1.1.1"
    port_name_oid = f"{port_name_oid_base}.{port_number}"

    user = UsmUserData(
        auth_user,
        auth_password,
        priv_password,
        auth_protocol,
        priv_protocol
    )

    for (error_indication, error_status, error_index, var_binds) in getCmd(
            SnmpEngine(),
            user,
            UdpTransportTarget((ip_address, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(port_name_oid)),
            lexicographicMode=False
    ):
        if error_indication:
            print(f"Error: {error_indication}")
            return "Unknown"
        elif error_status:
            print(f"Error: {error_status}")
            return "Unknown"
        else:
            for var_bind in var_binds:
                port_name = var_bind[1].prettyPrint()
                return port_name

def get_devices_primary_ip_by_role(api_url, headers, role):
    url_get_devices_by_role = f"{api_url}/dcim/devices/"
    params = {"role": role}

    response = requests.get(url_get_devices_by_role, headers=headers, params=params, verify=False)

    if response.status_code == 200:
        devices = response.json().get('results', [])

        if devices:
            for device in devices:
                manufacturer = device.get('device_type', {}).get('manufacturer', {}).get('name')

                primary_ip_info = device.get('primary_ip', {})
                primary_ip = primary_ip_info.get('address') if primary_ip_info else ""
                primary_ip_no_mask = primary_ip.split('/')[0]

                if manufacturer != "Aruba":
                    print("To nie aruba Ip: " + primary_ip_no_mask)

                    # Print VLAN list obtained from SNMP
                    vlan_list = get_vlan_list(primary_ip_no_mask, auth_user, auth_protocol, auth_password,
                                              priv_protocol, priv_password, oid_vlan_info)
                    print("Available VLANs:", vlan_list)

                    vlan_info = get_vlan_and_port_info(primary_ip_no_mask, auth_user, auth_protocol,
                                                        auth_password, priv_protocol, priv_password, vlan_list, port_membership_oid)

                    print(vlan_info)


                else:
                    print("To aruba " + primary_ip_no_mask)

        else:
            print(f"No devices found with role '{role}'.")
    else:
        print(f"Error retrieving devices. Status Code: {response.status_code}")
        print(response.text)

get_devices_primary_ip_by_role(api_url, headers, role_to_filter)
