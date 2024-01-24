import requests
import scapy.all as scapy

# Funkcja do skanowania sieci
def skanuj(ip):
    # Tworzenie obiektu ARP request
    arp_request = scapy.ARP(pdst=ip)

    # Tworzenie obiektu Ether broadcast
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # Łączenie ARP request i Ether broadcast
    arp_request_broadcast = broadcast/arp_request

    # Wysłanie pakietów ARP i odbiór odpowiedzi
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Przetwarzanie odpowiedzi i tworzenie listy klientów
    lista_klientow = []
    for element in answered_list:
        klient_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        lista_klientow.append(klient_dict)
    return lista_klientow

# Funkcja do sprawdzania istnienia prefixu
def sprawdz_czy_prefix_istnieje(prefix, api_url, naglowki):
    # Tworzenie URL do sprawdzenia istnienia prefixu
    url_sprawdzenie = f"{api_url}?prefix__contains={prefix}"
    print(url_sprawdzenie)
    # Wysłanie zapytania GET
    odpowiedz = requests.get(url_sprawdzenie, headers=naglowki)

    # Sprawdzenie kodu odpowiedzi i czy lista nie jest pusta
    if odpowiedz.status_code == 200 and odpowiedz.json() and isinstance(odpowiedz.json(), dict):
        # Sprawdzenie, czy w JSON jest klucz 'results'
        if 'results' in odpowiedz.json():
            results = odpowiedz.json()['results']

            # Iteracja przez wyniki i sprawdzenie, czy jest prefix o takiej samej wartości
            for result in results:
                if result.get('prefix') == prefix:
                    return True, result.get('id')  # Prefix już istnieje

        return False, None  # Brak prefixu o danej wartości
    elif odpowiedz.status_code == 404:
        return False, None  # Prefix nie istnieje
    else:
        print(f"Błąd podczas sprawdzania istnienia prefixu. Kod odpowiedzi: {odpowiedz.status_code}")
        print(odpowiedz.text)
        return None, None


# Funkcja do dodawania nowego prefixu
def dodaj_prefix(prefix_data, api_url, naglowki):
    # Wysłanie zapytania POST
    odpowiedz = requests.post(api_url, json={"prefix": prefix_data}, headers=naglowki)

    if odpowiedz.status_code == 201:
        print(f"Nowy prefix {prefix_data} został pomyślnie utworzony.")
    else:
        print(f"Błąd podczas tworzenia nowego prefixu {prefix_data}. Kod odpowiedzi: {odpowiedz.status_code}")
        print(odpowiedz.text)

# Funkcja do aktualizacji istniejącego prefixu
def aktualizuj_prefix(prefix_id, prefix_data, api_url, naglowki):
    # Tworzenie URL do aktualizacji prefixu
    url_aktualizacja = f"{api_url}{prefix_id}/"

    # Wysłanie zapytania PATCH
    odpowiedz = requests.patch(url_aktualizacja, json={"prefix": prefix_data}, headers=naglowki)

    if odpowiedz.status_code == 200:
        print(f"Prefix {prefix_data} został pomyślnie zaktualizowany.")
    else:
        print(f"Błąd podczas aktualizacji prefixu {prefix_data}. Kod odpowiedzi: {odpowiedz.status_code}")
        print(odpowiedz.text)
#testd dsadsaddasd s ad 31 31
# Ustawienia API
api_url = "http://192.168.1.10:8000/api/ipam/prefixes/"
api_token = "8a7fc18e627376eb14ab3d7c2d262c124f5ba02d"

# Nagłówki z tokenem autoryzacyjnym
naglowki = {
    "Authorization": f"Token {api_token}",
    "Content-Type": "application/json",
    "Accept": "application/json; indent=4"
}

# Skanowanie sieci
cel_ip = "192.168.1.1/24"
wyniki_skanowania = skanuj(cel_ip)

# Przygotowanie danych do zapytania POST
for klient in wyniki_skanowania:
    nowy_prefix_data = f"{klient['ip']}/32"  # Dodanie "_prefix" do nazwy prefixu
    # Sprawdzenie, czy prefix już istnieje
    prefix_istnieje, prefix_id = sprawdz_czy_prefix_istnieje(nowy_prefix_data, api_url, naglowki)

    if prefix_istnieje:
        # Jeśli prefix istnieje, wykonaj aktualizację
        aktualizuj_prefix(prefix_id, nowy_prefix_data, api_url, naglowki)
    else:
        # Jeśli prefix nie istnieje, wykonaj dodanie
        dodaj_prefix(nowy_prefix_data, api_url, naglowki)
