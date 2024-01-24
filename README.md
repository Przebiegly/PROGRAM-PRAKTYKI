# Skrypt do zarządzania prefixami IP - Dokumentacja

## Opis skryptu
Skrypt został stworzony w celu zarządzania prefixami IP w systemie, wykorzystując dostępne API. Obejmuje on trzy główne funkcje:
1. Skanowanie sieci w poszukiwaniu klientów i przygotowanie danych do zapytania POST.
2. Sprawdzanie istnienia prefixu w systemie.
3. Dodawanie nowego prefixu lub aktualizacja istniejącego.

## Wymagane biblioteki
- `requests`: Do obsługi zapytań HTTP.
- `scapy`: Do skanowania sieci i zbierania informacji o klientach.

## Konfiguracja
Przed uruchomieniem skryptu, należy dostosować poniższe ustawienia zgodnie z wymaganiami systemu oraz API:

```python
api_url = "http://192.168.1.10:8000/api/ipam/prefixes/"  # Adres URL API
api_token = "8a7fc18e627376eb14ab3d7c2d262c124f5ba02d"  # Token autoryzacyjny

naglowki = {
    "Authorization": f"Token {api_token}",
    "Content-Type": "application/json",
    "Accept": "application/json; indent=4"
}
```
## Funkcje skryptu

### 1. Funkcja `skanuj(ip)`
Funkcja ta służy do skanowania sieci w poszukiwaniu klientów. Wykorzystuje bibliotekę `scapy` do wysłania pakietów ARP i odbioru odpowiedzi. Zwraca listę klientów w formie słowników zawierających adres IP i MAC.

### 2. Funkcja `sprawdz_czy_prefix_istnieje(prefix, api_url, naglowki)`
Funkcja sprawdza istnienie prefixu w systemie poprzez zapytanie GET do API. Przyjmuje trzy argumenty: wartość prefixu, adres URL API oraz nagłówki z tokenem autoryzacyjnym. Zwraca wartość logiczną (`True` jeśli prefix istnieje, `False` jeśli nie) oraz identyfikator prefixu, jeśli ten istnieje.

### 3. Funkcje `dodaj_prefix(prefix_data, api_url, naglowki)` i `aktualizuj_prefix(prefix_id, prefix_data, api_url, naglowki)`
Funkcje te służą odpowiednio do dodawania nowego prefixu oraz aktualizacji istniejącego. Przyjmują trzy argumenty: dane prefixu, adres URL API oraz nagłówki z tokenem autoryzacyjnym. W przypadku błędu, wypisują informacje o nieudanej operacji.

```python
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
