## `Biblioteki`

```python
import requests
from pysnmp.hlapi import *
import urllib3
```
1. **requests**:
   - **Opis**: Biblioteka do wysyłania żądań HTTP w Pythonie.
   - **Użycie**: Wykorzystywana do komunikacji z serwerami HTTP, pobierania danych i interakcji z API.

2. **pysnmp.hlapi**:
   - **Opis**: Moduł do pracy z protokołem SNMP w Pythonie.
   - **Użycie**: Umożliwia wykonywanie operacji SNMP, takich jak zapytania i ustawianie wartości.

3. **Urllib3**:
   - **Opis**: Potężna biblioteka klienta HTTP w Pythonie.
   - **Użycie**: Wykorzystywana do wysyłania żądań HTTP, konsumowania API i pobierania zasobów z sieci.
   

## `Zmienne` 
```python
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
```
- `urllib3.disable_warnings()`: Ta linia kodu służy do wyłączenia ostrzeżeń generowanych przez bibliotekę urllib3. Stosuje się to podczas wykonywania żądań HTTPS do serwerów z certyfikatami SSL, które są samopodpisane lub w inny sposób niezaufane, ponieważ urllib3 może generować ostrzeżenia dotyczące procesu weryfikacji SSL.

- `api_url = "https://192.168.99.10/api"`: Zmienna `api_url` jest przypisana do wartości łańcuchowej `"https://192.168.99.10/api"`, która reprezentuje bazowy adres URL interfejsu API, do którego następuje dostęp.

- `api_token = "2f5294f72819946284d36e7bccb42380cfd9ca92"`: Zmienna `api_token` jest przypisana do wartości łańcuchowej `"2f5294f72819946284d36e7bccb42380cfd9ca92"`, która służy jako token uwierzytelniający wymagany do dostępu do interfejsu API.

- `headers = {...}`: Słownik `headers` zawiera pary klucz-wartość reprezentujące nagłówki HTTP. Zawiera:
  - `"Authorization"`: Ten nagłówek jest konstruowany za pomocą f-stringów, włączając wcześniej uzyskany token, zgodnie z formatem `"Token {api_token}"`.
  - `"Content-Type"`: Ten nagłówek wskazuje na typ zawartości żądania HTTP i ma wartość `"application/json"`.

- `role_to_filter = "switch"`: Zmienna `role_to_filter` jest przypisana do wartości łańcuchowej `"switch"`, która wskazuje na rolę, która ma być filtrowana lub przetwarzana w ramach operacji wykonywanych na interfejsie API.

- `auth_user = "botUser"`: Zmienna `auth_user` jest przypisana do wartości łańcuchowej `"botUser"`, która reprezentuje nazwę użytkownika wykorzystywaną do uwierzytelniania.

- `auth_protocol = usmHMACSHAAuthProtocol`: Zmienna `auth_protocol` odnosi się do protokołu uwierzytelniania, ale brakuje informacji na temat jego dokładnej implementacji lub pochodzenia.

- `auth_password = "j4p3UbaWEveVWz2omitn"`: Zmienna `auth_password` jest przypisana do wartości łańcuchowej `"j4p3UbaWEveVWz2omitn"`, która reprezentuje hasło użytkownika wykorzystywane w procesie uwierzytelniania.

- `priv_protocol = usmAesCfb128Protocol`: Zmienna `priv_protocol` odnosi się do protokołu używanego do szyfrowania prywatnych danych, ale brakuje informacji na temat jego dokładnej implementacji lub pochodzenia.

- `priv_password = "Q2yJk7uuSz9iqVhEoxyz"`: Zmienna `priv_password` jest przypisana do wartości łańcuchowej `"Q2yJk7uuSz9iqVhEoxyz"`, która reprezentuje hasło używane do szyfrowania prywatnych danych.

- `priv_protocol_Aruba = usmDESPrivProtocol`: Zmienna `priv_protocol_Aruba` odnosi się do protokołu używanego do szyfrowania prywatnych danych w kontekście urządzeń sieciowych Aruba, ale brakuje informacji na temat jego dokładnej implementacji lub pochodzenia.

- `priv_password_Aruba = "c5ecae92ae2bd3c253c2"`: Zmienna `priv_password_Aruba` jest przypisana do wartości łańcuchowej `"c5ecae92ae2bd3c253c2"`, która reprezentuje hasło używane do szyfrowania prywatnych danych w kontekście urządzeń sieciowych Aruba.



##  `Funkcjia get_vlan_list`

```python
def get_vlan_list(ip_address, auth_user, auth_protocol, auth_password, priv_protocol, priv_password, oid):
    user = UsmUserData(
        auth_user,
        auth_password,
        priv_password,
        auth_protocol,
        priv_protocol
    )
    transport_target = UdpTransportTarget((ip_address, 161))

    vlan_ids = []  

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
            return None  
        elif error_status:
            print(f"Error: {error_status}")
            return None  
        else:
            for var_bind in var_binds:
                oid_str = var_bind[0].prettyPrint()  
                vlan_num = oid_str.split(".")[-1]  
                vlan_ids.append(int(vlan_num))  
    return vlan_ids 
```
### Cel Funkcji:
Funkcja `get_vlan_list` służy do pobierania listy identyfikatorów VLAN (Virtual Local Area Network) z urządzenia sieciowego przy użyciu protokołu SNMP (Simple Network Management Protocol).

### Parametry:
- `ip_address`: Ciąg znaków reprezentujący adres IP urządzenia sieciowego, z którego ma zostać pobrana informacja o VLAN.
- `auth_user`: Ciąg znaków określający nazwę użytkownika do uwierzytelnienia SNMP.
- `auth_protocol`: Ciąg znaków określający protokół uwierzytelniania do użycia w SNMP, np. MD5 lub SHA.
- `auth_password`: Ciąg znaków reprezentujący hasło do uwierzytelniania SNMP.
- `priv_protocol`: Ciąg znaków określający protokół prywatności (szyfrowania) do użycia w SNMP, np. AES lub DES.
- `priv_password`: Ciąg znaków reprezentujący hasło do prywatności SNMP.
- `oid`: Ciąg znaków reprezentujący identyfikator obiektu (OID) do zapytania o informacje o VLAN.

### Kroki Funkcji:

1. **Inicjalizacja Danych Użytkownika SNMP:**
   - Tworzenie danych użytkownika SNMP przy użyciu podanych parametrów uwierzytelniania i prywatności.

2. **Ustawienie Celu Transportu:**
   - Określenie celu transportu przy użyciu podanego adresu IP i portu SNMP (161).

3. **Inicjalizacja Listy ID VLAN:**
   - Utworzenie pustej listy do przechowywania identyfikatorów VLAN pobranych z urządzenia sieciowego.

4. **Pobieranie Informacji o VLAN:**
   - Iteracja przez odpowiedzi SNMP przy użyciu funkcji `nextCmd`.
   - Obsługa ewentualnych błędów, które mogą wystąpić podczas zapytania SNMP.
   - Wyodrębnianie identyfikatorów VLAN z odpowiedzi SNMP i dodawanie ich do listy ID VLAN.

5. **Zwracanie ID VLAN:**
   - Zwracanie listy identyfikatorów VLAN pobranych z urządzenia sieciowego.

### Obsługa Błędów:
- Jeśli wystąpi wskazanie błędu podczas zapytania SNMP, wyświetlany jest komunikat błędu, a funkcja zwraca `None`.
- Jeśli podczas zapytania SNMP napotkano status błędu, wyświetlany jest komunikat błędu, a funkcja zwraca `None`.
- Jeśli nie wystąpią żadne błędy, funkcja zwraca listę identyfikatorów VLAN.

### Dodatkowe Uwagi:
- Funkcja zakłada dostępność usług SNMP na docelowym urządzeniu sieciowym.
- Należy podać prawidłowe poświadczenia uwierzytelniania i autoryzacji dla poprawnej komunikacji SNMP.


## `Funkcja get_vlan_and_port_info`

```python
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
```

### Opis:
Funkcja `get_vlan_and_port_info` służy do pobierania informacji o przypisanych portach dla określonych numerów VLAN na urządzeniu przy użyciu protokołu SNMP.

### Parametry:
- `ip_address`: Adres IP urządzenia, z którego chcemy pobrać informacje. (Typ: string)
- `auth_user`: Nazwa użytkownika do uwierzytelniania SNMP. (Typ: string)
- `auth_protocol`: Protokół uwierzytelniania SNMP (np. 'MD5', 'SHA'). (Typ: string)
- `auth_password`: Hasło do uwierzytelniania SNMP. (Typ: string)
- `priv_protocol`: Protokół szyfrowania SNMP (np. 'DES', 'AES'). (Typ: string)
- `priv_password`: Hasło do szyfrowania SNMP. (Typ: string)
- `vlan_ids`: Lista numerów VLAN, dla których chcemy pobrać informacje o przypisanych portach. (Typ: lista int)
- `port_membership_oid`: OID (Object Identifier) bazowy dla informacji o przynależności portów do VLAN-u. (Typ: string)

### Działanie:
1. Tworzy obiekt `UsmUserData` z danymi uwierzytelniającymi SNMP, na podstawie przekazanych parametrów.
2. Sprawdza, czy lista numerów VLAN (`vlan_ids`) nie jest pusta. Jeśli jest, wyświetla komunikat o pustej liście i kończy działanie funkcji.
3. Iteruje przez każdy numer VLAN w liście `vlan_ids`.
4. Tworzy bazowy OID dla informacji o przynależności portów do danego VLAN-u, korzystając z OID-a podanego w parametrze `port_membership_oid` oraz numeru VLAN.
5. Wykonuje zapytanie SNMP do urządzenia, aby pobrać informacje o przypisanych portach dla danego VLAN-u, używając modułu `pysnmp`.
6. Obsługuje ewentualne błędy, które mogą wystąpić podczas zapytania SNMP.
7. Dla każdej przynależności portu do VLAN-u, wywołuje funkcję `print_port_info` w celu wyświetlenia informacji o przypisanym porcie.

### Zwracane wartości:
Funkcja wyświetla informacje o przypisanych portach dla określonych numerów VLAN.