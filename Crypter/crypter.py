#!/usr/bin/env python3
# Judul.......: Crypter
# Deskripsi...: Crack kata sandi Linux 
# Pembuat.....: BgRopay
# Penggunaan..: python3 crypter.py
# Github .....: github.com/bgropay/crypter

import os
import crypt
import platform
import colorama

# Warna 
h = colorama.Fore.LIGHTGREEN_EX # Hijau 
b = colorama.Fore.LIGHTBLUE_EX  # Biru 
c = colorama.Fore.LIGHTCYAN_EX  # Cyan
p = colorama.Fore.LIGHTWHITE_EX # Putih 
m = colorama.Fore.LIGHTRED_EX   # Merah 
r = colorama.Fore.RESET         # Reset 

# Periksa apakah sistem operasinya Linux
if platform.system() != 'Linux':
    print(f"{m}[-] {p}Program ini dirancang untuk dijalankan hanya pada sistem operasi Linux.{r}")
    exit(1)

os.system("clear")

print(f"""{p} ___________________________{r}
{p}< {c}Selamat datang di Crypter {p}>{r}
 {p}---------------------------{r}
{p}        \   ^__^{r}
{p}         \  (oo)\_______{r}
{p}            (__)\       )\/{r}
{p}                ||----w |{r}
{p}                ||     ||{r}
""")

# Masukkan jalur ke file Passwd
while True:
    try:
        file_passwd = input(f"{c}[»] {p}Masukkan jalur ke file Passwd (contoh: /etc/passwd): ")
        # kondisi jika file Passwd tidak ditemukan
        if not os.path.isfile(file_passwd):
            print(f"{m}[-] {p}File Passwd '{file_passwd}' tidak ditemukan.{r}")
            continue
        break
    except KeyboardInterrupt:
        print(f"\n{m}[-] {p}Berhenti...{r}")
        exit(1)
    
# Masukkan jalur ke file Shadow 
while True:
    try:
        file_shadow = input(f"{c}[»] {p}Masukkan jalur ke file Shadow (contoh: /etc/shadow): ")
        # kondisi jika file Shadow tidak ditemukan 
        if not os.path.isfile(file_shadow):
            print(f"{m}[-] {p}File Shadow '{file_shadow}' tidak ditemukan.{r}")
            continue
        break
    except KeyboardInterrupt:
        print(f"\n{m}[-] {p}Berhenti...{r}")
        exit(1)

# Masukkan jalur ke file Wordlist 
while True:
    try:
        file_wordlist = input(f"{c}[»] {p}Masukkan jalur ke file Wordlist: ")
        # kondisi jika file Wordlist tidak ditemukan
        if not os.path.isfile(file_wordlist):
            print(f"{m}[-] {p}File wordlist '{file_wordlist}' tidak ditemukan.{r}")
            continue
        break
    except KeyboardInterrupt:
        print(f"\n{m}[-] {p}Berhenti...{r}")
        exit(1)

# Output file
output_file = "hash.txt"

dict_passwd = {}
dict_shadow = {}

# Baca file /etc/passwd
with open(file_passwd, 'r') as passwd:
    for baris in passwd:
        bagian = baris.strip().split(':')
        if len(bagian) > 1:
            nama_pengguna = bagian[0]
            gecos = bagian[4]  # Extract GECOS field
            if 'user' in gecos.lower():  # Check for 'user' in GECOS
                dict_passwd[nama_pengguna] = bagian

# Baca file /etc/shadow 
with open(file_shadow, 'r') as shadow:
    for baris in shadow:
        bagian = baris.strip().split(':')
        if len(bagian) > 1:
            nama_pengguna = bagian[0]
            if nama_pengguna in dict_passwd:
                dict_shadow[nama_pengguna] = bagian 

# Gabungkan informasi untuk pengguna yang ada di kedua file
with open(output_file, 'w') as output:
    for nama_pengguna in dict_passwd:
        if nama_pengguna in dict_shadow:
            bagian_passwd = dict_passwd[nama_pengguna]
            bagian_shadow = dict_shadow[nama_pengguna]
            digabungkan = ':'.join([
                bagian_passwd[0],  # Nama pengguna 
                bagian_shadow[1],  # Kata sandi Hash
                bagian_passwd[2],  # UID
                bagian_passwd[3],  # GID
                bagian_passwd[4],  # GECOS
                bagian_passwd[5],  # home directory
                bagian_passwd[6]   # shell
            ])
            output.write(digabungkan + '\n')

jumlah_yang_berhasil_di_crack = 0
pengguna_yang_berhasil_di_crack = []

with open(file_wordlist, "r", encoding="latin-1", errors="ignore") as wordlist:
    daftar_kata_sandi = wordlist.readlines()
    jumlah_kata_sandi = len(daftar_kata_sandi)
    print(f"{b}[*] {p}Jumlah kata sandi dalam file Wordlist: {b}{jumlah_kata_sandi}{r}")

for nama_pengguna in dict_shadow:
    kata_sandi_hash = dict_shadow[nama_pengguna][1]
    print(f"{h}[+] {p}Menemukan nama pengguna: {h}{dict_shadow[nama_pengguna][0]}{r}")
    print(f"{b}[*] {p}Meng-crack kata sandi untuk nama pengguna: {b}{dict_shadow[nama_pengguna][0]}{p}...{r}")
    kata_sandi_ditemukan = False
    for kata_sandi in daftar_kata_sandi:
        kata_sandi = kata_sandi.strip()
        try:
            # Crack Kata Sandi Linux dengan Crypt
            if crypt.crypt(kata_sandi, kata_sandi_hash) == kata_sandi_hash:
                print(f"{h}[+] {p}Kata sandi berhasil di-crack untuk nama pengguna: {h}{nama_pengguna}{p}, kata sandinya adalah: {h}{kata_sandi}{r}")
                pengguna_yang_berhasil_di_crack.append((nama_pengguna, kata_sandi))
                jumlah_yang_berhasil_di_crack += 1
                kata_sandi_ditemukan = True
                break
        except KeyboardInterrupt:
            print(f"\n{m}[-] {p}Berhenti...{r}")
            exit(1)
            
    if not kata_sandi_ditemukan:
        print(f"{m}[-] {p}Kata sandi gagal di-crack untuk nama pengguna: {m}{nama_pengguna}{r}")

print(f"{h}\n[+] {p}Jumlah nama pengguna yang berhasil di-crack: {h}{jumlah_yang_berhasil_di_crack}{r}")
for nama_pengguna, kata_sandi in pengguna_yang_berhasil_di_crack:
    print(f"{h}[+] {p}Nama pengguna: {h}{nama_pengguna}{p}, kata sandi: {h}{kata_sandi}{r}")
