import requests
from pysnmp.hlapi import *
from pysnmp.hlapi import usmHMACSHAAuthProtocol, usmAesCfb128Protocol
import urllib3

urllib3.disable_warnings()

api_url = "https://192.168.99.10/api"
api_token = "2f5294f72819946284d36e7bccb42380cfd9ca92"

headers = {
    "Authorization": f"Token {api_token}",
    "Content-Type": "application/json"
}

auth_user = "botUser"
auth_protocol = usmHMACSHAAuthProtocol #szyfrowanie rodzaj
auth_password = "j4p3UbaWEveVWz2omitn"  # haslo
priv_protocol = usmAesCfb128Protocol # szyfrowanie AES
priv_password = "Q2yJk7uuSz9iqVhEoxyz" #i tu ten klucz do AES
oid_hostname = "1.3.6.1.2.1.1.5.0" # daje hostname sprawdza czy dziala snmp dla ip (mozna potem uzunac)
oid_base = "1.3.6.1.2.1.31.1.1.1.1" # to nie wiem
role_to_filter = "switch" #tylko switch
oid_ports = "1.3.6.1.2.1.2.2.1" #daje wszyskie poty
oid_mac = "1.3.6.1.2.1.2.2.1.6" #daje adresy mac dla portow


def get_devices_primary_ip_by_role(api_url, headers, role): # TU WSZYSTKO WYWYOLUJE
    url_get_devices_by_role = f"{api_url}/dcim/devices/"
    params = {"role": role}

    response = requests.get(url_get_devices_by_role, headers=headers, params=params, verify=False)

    if response.status_code == 200:
        devices = response.json().get('results', [])
        if devices:
            for device in devices:
                device_name = device.get('name')
                role_name = device.get('device_role', {}).get('name')
                primary_ip_info = device.get('primary_ip', {})
                primary_ip = primary_ip_info.get('address') if primary_ip_info else "N/A"
                primary_ip_no_mask = primary_ip.split('/')[0]
                hostname = snmp_walk_v3_pobierz_hostname(primary_ip_no_mask, auth_user, auth_protocol, auth_password,
                                                         priv_protocol, priv_password, oid_hostname)
                print(f"Device: {device_name}, Role: {role_name}, Primary IP: {primary_ip}, Hostname: {hostname}")
                tomasz = snmp_walk_v3_get_ports(primary_ip_no_mask, auth_user, auth_protocol, auth_password,
                                                        priv_protocol, priv_password, oid_ports)
                print(tomasz)
                # find_and_print_duplicate_mac_ports(primary_ip_no_mask, oid_mac)
                result = snmp_walk_v3_pobierz_mac(primary_ip_no_mask, auth_user, auth_protocol, auth_password,
                                                        priv_protocol, priv_password, oid_mac)
                print(result)
        else:
            print(f"No devices found with role '{role}'.")
    else:
        print(f"Error retrieving devices. Status Code: {response.status_code}")
        print(response.text)

def find_and_print_duplicate_mac_ports(adres, oid):
    mac_list = snmp_walk_v3_pobierz_mac(adres, auth_user, auth_protocol, auth_password, priv_protocol, priv_password, oid)
    if mac_list:
        all_macs = mac_list
        duplicate_macs = find_duplicate_macs(all_macs)

        for duplicate_mac in duplicate_macs:
            print_switch_port_mapping(adres, duplicate_mac)

def find_duplicate_macs(mac_list):
    seen_macs = set()
    duplicates = []

    for mac in mac_list:
        if mac in seen_macs:
            duplicates.append(mac)
        else:
            seen_macs.add(mac)

    return duplicates

def print_switch_port_mapping(ip_switch, duplicate_mac):
    # Add logic to retrieve and print IP switch's port associated with the duplicate MAC address
    print(f"Ip switcha {ip_switch}, dla MAC {duplicate_mac}")

def snmp_walk_v3_pobierz_mac(adres, auth_user, auth_protocol, auth_password, priv_protocol, priv_password, oid): #DAJE ADRESSY MAC DLA PORTOW
    user = UsmUserData(
        auth_user,
        auth_password,
        priv_password,
        auth_protocol,
        priv_protocol
    )
    oid_object = ObjectType(ObjectIdentity(oid))
    transport_target = UdpTransportTarget((adres, 161))
    mac_addresses = []

    print(f"Pobieranie MAC address dla {adres}...")
    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
            SnmpEngine(),
            user,
            transport_target,
            ContextData(),
            oid_object,
            lexicographicMode=False
    ):

        if errorIndication:
            print(f"Błąd: {errorIndication}")
            return None
        elif errorStatus:
            print(f"Błąd: {errorStatus}")
            return None
        else:
            for varBind in varBinds:
                if varBind[0].prettyPrint():
                    print(f"Mac: {varBind[1].prettyPrint()}")
                    mac_addresses.append(varBind[1].prettyPrint())

    return mac_addresses


def snmp_walk_v3_get_ports(adres, auth_user, auth_protocol, auth_password, priv_protocol, priv_password, oid): #DAJE WSZYSTKIE PORTY DLA SWITCHA
    user = UsmUserData(
        auth_user,
        auth_password,
        priv_password,
        auth_protocol,
        priv_protocol
    )
    oid_object = ObjectType(ObjectIdentity(oid))
    transport_target = UdpTransportTarget((adres, 161))
    print(f"Fetching port information for {adres}...")
    port_info = []
    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
            SnmpEngine(),
            user,
            transport_target,
            ContextData(),
            oid_object,
            lexicographicMode=False
    ):
        if errorIndication:
            print(f"Error: {errorIndication}")
            break
        elif errorStatus:
            print(f"Error: {errorStatus}")
            break
        else:
            for varBind in varBinds:
                oid = varBind[0]
                value = varBind[1]
                print(f"OID: {oid.prettyPrint()}, Value: {value.prettyPrint()}")
                port_info.append(value.prettyPrint())

    return port_info


def snmp_walk_v3_pobierz_hostname(adres, auth_user, auth_protocol, auth_password, priv_protocol, priv_password, oid): #DAJE HOSNAME DLA SWITCHA PO IP (SNMP NIE NETBOX)
    user = UsmUserData(
        auth_user,
        auth_password,
        priv_password,
        auth_protocol,
        priv_protocol
    )
    oid_object = ObjectType(ObjectIdentity(oid))
    transport_target = UdpTransportTarget((adres, 161))
    print(f"Pobieranie nazwy hosta dla {adres}...")
    for (errorIndication, errorStatus, errorIndex, varBinds) in getCmd(SnmpEngine(), user, transport_target,
                                                                       ContextData(), oid_object):
        if errorIndication:
            print(f"Błąd: {errorIndication}")
            break
        elif errorStatus:
            print(f"Błąd: {errorStatus}")
            break
        else:
            for varBind in varBinds:
                if varBind[0].prettyPrint():
                    print(f"Nazwa hosta: {varBind[1]}.prettyPrint()")
                    return varBind[1].prettyPrint()

get_devices_primary_ip_by_role(api_url, headers, role_to_filter)
