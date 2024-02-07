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



def get_vlan_and_port_info(ip_address, auth_user, auth_protocol, auth_password, priv_protocol, priv_password, ports,
                            vlan_info_oid):
    vlan_ids = get_vlan_list(ip_address, auth_user, auth_protocol, auth_password, priv_protocol, priv_password,
                             vlan_info_oid)
    vlan_and_port_info = {}

    # Sprawdzenie, czy lista VLANów nie jest pusta lub None
    if not vlan_ids:
        print("Brak dostępnych informacji o VLANach.")
        return vlan_and_port_info  # Zwróć pustą listę

    for (error_indication, error_status, error_index, var_binds) in nextCmd(
            SnmpEngine(),
            UsmUserData(auth_user, auth_password, priv_password, auth_protocol, priv_protocol),
            UdpTransportTarget((ip_address, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(ports)),
            lexicographicMode=False
    ):
        if error_indication:
            print(f"Błąd: {error_indication}")
            break
        elif error_status:
            print(f"Błąd: {error_status}")
            break
        else:
            port_index = var_binds[0][0][-1]
            vlan_ids_for_port = var_binds[0][1].prettyPrint().split()
            port_vlans = []
            for vlan_id in vlan_ids_for_port:
                if int(vlan_id) in vlan_ids:
                    port_vlans.append(vlan_id)
            vlan_and_port_info[port_index] = {"VLANs": port_vlans}

            print(f"Przetwarzanie portu {port_index}: VLANy {port_vlans}")

    return vlan_and_port_info



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
                    print("Available VLANs:", get_vlan_list(primary_ip_no_mask, auth_user, auth_protocol, auth_password,
                                                            priv_protocol, priv_password, oid_vlan_info))

                    informacje_vlanu_i_portu = get_vlan_and_port_info(primary_ip_no_mask, auth_user,
                                                                      auth_protocol, auth_password,
                                                                      priv_protocol, priv_password, oid_ports,
                                                                      oid_vlan_info)
                    print(informacje_vlanu_i_portu)
                    for port, info in informacje_vlanu_i_portu.items():
                        if 'VLANs' in info:
                            print(f"Port {port}: VLAN {info['VLANs']}")
                        else:
                            print(f"Port {port}: VLAN None")  # Dodanie obsługi braku VLANu dla danego portu

                else:
                    print("To aruba " + primary_ip_no_mask)

        else:
            print(f"No devices found with role '{role}'.")
    else:
        print(f"Error retrieving devices. Status Code: {response.status_code}")
        print(response.text)

get_devices_primary_ip_by_role(api_url, headers, role_to_filter)
