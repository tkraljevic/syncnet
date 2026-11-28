# syncnet: opis protokola (nacrt)

Nacrt od 18. 11. 2026. Opisuje žicu kakvu danas govori kod iz kojeg
syncnet nastaje. Nije dovršen i smije se promijeniti.

Ovaj opis je za onoga tko piše drugu izvedbu ili aplikaciju nad
bibliotekom. Kaže što putuje među računalima, kojim redom i u kojem
obliku. Kako biblioteka to iznutra radi, ovdje ne piše.

Gdje se opis i kod ne slažu, vrijedi kod. Stalni ulazi i točni bajtovi
za provjeru druge izvedbe su u ispitnim vektorima (mapa `vektori`).

## 1. Slika

Svako računalo ima svoju bazu i svoj ključ. Nijedno nije izvor istine.
Računala iste mreže povremeno razgovaraju u parovima i jedno drugome daju
ono što ono još nema.

Sve što se dijeli zapisano je kao niz **verzija**. Svaka izmjena zapisa je
nova verzija, a brisanje je verzija s oznakom da je zapis uklonjen. Verzije
se ne mijenjaju i ne brišu u prijenosu.

Povjerenje ima tri sloja:

1. **Uparivanje.** Dva čovjeka na dva zaslona vide isti kod od šest
   znamenki i oba potvrde.
2. **Članstvo.** Računalo je član mreže kad ima potvrdu potpisanu ključem
   mreže, ili ključem računala koje je mreža ovlastila da prima članove.
3. **Opoziv.** Potpisan zapis koji članstvo ili ovlast poništava.

Razmjena ide samo među članovima iste mreže.

## 2. Pojmovi

| Pojam | Značenje |
|---|---|
| računalo (čvor) | jedna instalacija aplikacije: svoja baza, svoj ključ i ime |
| ime računala | tekst po kojem se računalo zove u mreži; ne smije sadržavati `\|` |
| verzija | jedan nepromjenjiv zapis o stanju jednog zapisa aplikacije |
| oznaka verzije | UUIDv7; poredak oznaka je poredak nastanka |
| autor | ime računala na kojem je verzija nastala |
| kanal | tekst koji verzije dijeli u skupine; prazan kanal drže svi članovi |
| ključ granice | `autor` za prazan kanal, inače `autor\|kanal` |
| granica | za svaki ključ granice najveća oznaka verzije koju računalo ima |
| delta | verzije iznad tuđe granice, u kanalima koje druga strana želi |
| otisak | SHA-256 bajtova, 64 mala heksadecimalna znaka |
| pozivatelj, pozvani | tko je otvorio vezu i tko ju je primio |

## 3. Što daje aplikacija

Biblioteka nema svoje zadane vrijednosti. Aplikacija zadaje:

| Što | Gdje se koristi |
|---|---|
| ime protokola | ime certifikata, pronalaženje, uparivanje, potpisi signala, ključevi udaraca, ALPN |
| oznake formata | vjerodajnice u certifikatu, zahtjev i potvrda primanja na daljinu, kopija ključa mreže |
| portove | razmjena, uparivanje, pronalaženje, WEB sync |
| vrste zapisa i njihove sheme | polje `vrste` u granici |
| značenje kanala | biblioteci je kanal samo tekst |
| pravilo „želim li ovaj kanal” | što se šalje i što se prima |
| dodatne oznake mogućnosti i korake | proširenja razgovora |

**Ime protokola** ima najviše 32 znaka: mala slova i brojke, a crtica samo
između njih. Računala s različitim imenom protokola ne mogu se upariti ni
razmjenjivati: ime ulazi u certifikat, u kod uparivanja i u svaki potpis.

Dvije aplikacije ne smiju dijeliti ime protokola. Testna mreža iste
aplikacije uzima drugo ime, npr. s nastavkom `-sim`.

## 4. Ključevi i zapis ključa

- Ključ računala je Ed25519. Čuva se u datoteci uz bazu, nikad u bazi, pa
  kopija baze ne nosi identitet računala.
- Ključ mreže je Ed25519. Privatni dio drže samo računala koja smiju
  primati članove. Javni dio drži svaki član.
- Javni ključ se svuda piše kao standardni base64 s dopunom (44 znaka za 32
  bajta).

## 5. TLS

Sve veze razmjene i uparivanja idu kroz TLS 1.3.

- Obje strane pokazuju certifikat. Certifikat je samopotpisan ključem
  računala. Nema izdavatelja kojem se vjeruje: vjeruje se ključu.
- Ime certifikata (CN) je `<protokol>-sync`.
- Strana koja primi certifikat provjerava redom: da je ključ Ed25519, pa da
  je CN točan. Certifikat s drugim CN-om znači drugu mrežu ili drugu
  aplikaciju i veza se prekida bez poruke.
- U razmjeni certifikat nosi **vjerodajnice**: JSON
  `{"clanstvo": …, "ovlast": …}` računala, u polju SAN kao URI
  `urn:<oznaka vjerodajnica><base64url bez dopune>`. Čita se najviše
  16 KiB. Uparivanje ide bez vjerodajnica.
- Na TCP vezama razmjene i uparivanja ALPN se ne postavlja. Signal ima
  ALPN `<protokol>-signal/1`, a WEB sync `<protokol>-web/1`.

**Pozivatelj** zna koji ključ druga strana mora dokazati: uzima ga iz
njezina članstva, ne iz zapisa koji o njoj kruži mrežom. Drugu stranu
provjerava usred rukovanja, prije nego što pošalje svoj certifikat. Tako
računalo koje se lažno javi na poznatoj adresi ne dobije tuđe članstvo.

**Pozvani** nakon rukovanja provjeri da ključ pripada članu: ili ima
valjano, neopozvano članstvo te mreže pod tim imenom, ili vjerodajnice iz
certifikata vode do ključa mreže. Tko ne prođe, veza mu se zatvara bez
poruke. Iznimka je WEB sync: tamo nečlan dobije kod `0x0104` i zatvara se
cijela sesija.

## 6. Uparivanje

Uparivanje je zasebna TLS veza, bez vjerodajnica. Poruke su JSON objekti,
jedan za drugim.

1. Obje strane pošalju `Hello`:

   | Polje | Tip | Značenje |
   |---|---|---|
   | `protocol` | tekst | ime protokola; mora biti isto |
   | `deviceId` | tekst | ime računala |
   | `name` | tekst | ime za prikaz čovjeku |
   | `version` | tekst | izdanje aplikacije |
   | `meta` | mapa tekst → tekst, izostaje kad je prazna | što aplikacija želi javiti prije odluke; tvrdnja, ne dokaz |
   | `sas` | cijeli broj | inačica dogovora koda; mora biti najmanje 2 |

2. Dogovor koda s obvezom. Svaka strana izabere nasumičan broj od 32
   bajta.
   - pozivatelj pošalje `{"obveza": …}`, gdje je obveza
     SHA-256(`<protokol>-pair-commit-v2|` ‖ broj pozivatelja);
   - pozvani pošalje `{"broj": …}`, svoj broj;
   - pozivatelj pošalje `{"broj": …}`, svoj broj;
   - pozvani provjeri da broj odgovara obvezi.

   Bajtovi su u JSON-u base64.
3. Kod od šest znamenki. Računa se SHA-256 nad, redom:
   `<protokol>-pair-v2|`, manji javni ključ, veći javni ključ (uspoređeni
   kao bajtovi), broj pozivatelja, broj pozvanog. Prva četiri bajta sažetka
   čitaju se kao broj bez predznaka (big-endian), uzima se ostatak pri
   dijeljenju s 1 000 000 i piše sa šest znamenki, s vodećim nulama.
   Ispitni vektor `uparivanje.kodSNulom` daje kod koji počinje nulom
   (`020062`). Izvedba koja kod piše bez vodećih nula na njemu padne.
   Vektor `uparivanje.kodSNajvisimBitom` ima sažetak koji počinje bajtom
   `0xc5`, pa na njemu padne izvedba koja broj čita s predznakom.
4. Oba čovjeka usporede kod i potvrde. Svaka strana pošalje
   `Confirm`: `{"approved": true|false, "payload": …}`. Ništa se ne sprema
   dok obje strane ne potvrde.

`payload` u `Confirm` nosi ono što uparivanje predaje: ime i javni ključ
mreže, članstvo pošiljatelja i, kad pošiljatelj smije primati članove,
novo članstvo za drugu stranu.

Granice: `Hello` 64 KiB, korak koda 4 KiB, `Confirm` 1 MiB.

Napomena: obje strane pošalju `Hello` (ime računala, ime za prikaz,
izdanje i `meta`) prije dogovora koda. Dok računalo čeka uparivanje, te
podatke dobije svatko tko se spoji na port uparivanja, i bez koda. To je
poznato i otvoreno pitanje koje treba riješiti prije prvog izdanja.
Protokol se zbog toga zasad ne mijenja.

## 7. Članstvo, ovlast i opoziv

Sva tri zapisa potpisana su Ed25519. Potpis je nad **kanonskim bajtovima**:
zbijenim JSON-om s poljima točno ovim redom, a vremena su cijele sekunde
Unix vremena. Potpis se piše kao standardni base64.

Kanonski JSON je onakav kakav piše Go (`encoding/json`): bez razmaka, a
znakovi `<`, `>` i `&` u tekstu pišu se kao `\u003c`, `\u003e` i
`\u0026`. Druga izvedba mora pisati isto, inače potpis ne vrijedi za ime
koje sadrži takav znak.

### Ovlast

Ovlast daje računalu pravo da prima članove. Potpisuje je samo ključ
mreže.

Polja zapisa: `network`, `deviceId`, `deviceKey`, `issuedBy`, `issuedAt`,
`expiresAt`, `signature`.

Kanonski bajtovi:

```json
{"v":"ovlast/1","network":"…","deviceId":"…","deviceKey":"…","issuedBy":"…","issuedAt":1760000000,"expiresAt":1760003600}
```

### Članstvo

Polja zapisa: `network`, `deviceId`, `deviceKey`, `issuedBy`, `issuedAt`,
`expiresAt`, `signature` i, samo kad ga je potpisao ovlašteni primatelj,
`primatelj` (njegova cijela ovlast).

Kanonski bajtovi kad potpisuje ključ mreže:

```json
{"v":1,"network":"…","deviceId":"…","deviceKey":"…","issuedBy":"…","issuedAt":1760000000,"expiresAt":1760003600}
```

Kanonski bajtovi kad potpisuje ovlašteni primatelj (polje `ovlast` je
potpis njegove ovlasti):

```json
{"v":2,"network":"…","deviceId":"…","deviceKey":"…","issuedBy":"…","issuedAt":1760000000,"expiresAt":1760002800,"ovlast":"…"}
```

U zapisu su vremena u obliku RFC 3339, a u kanonskim bajtovima cijele
sekunde. Zato se vrijeme pri izdavanju reže na sekundu.

Za članstvo koje je potpisao ovlašteni primatelj vrijedi još:

- njegova ovlast mora vrijediti u trenutku `issuedAt` članstva;
- članstvo ne smije trajati dulje od ovlasti;
- `issuedAt` ne smije biti više od jednog sata ispred sata onoga tko
  provjerava;
- `issuedBy` članstva mora biti `deviceId` ovlasti.

Ovlast nema pričuve: ne vrijedi prije `issuedAt` ni nakon `expiresAt`.

Članstvo vrijedi kad: potpis vrijedi, mreža je prava, ključ računala je
onaj koji je dokazan u TLS-u, nije opozvano i nije isteklo. Isteklo
članstvo za razmjenu vrijedi još 30 dana pričuve, da istek sam ne raspadne
mrežu. Kad za isto ime računala vrijede dva članstva s različitim
ključem, vrijedi ono koje je prvo izdano.

Potpis se provjerava kad se članstvo koristi, ne kad zapis stigne.

### Opoziv

Polja zapisa: `id`, `vrsta` (`clanstvo` ili `ovlast`), `nodeId`,
`publicKey`, `issuedAt`, `opozvanoAt`, `opozvao`, `potpisnik`, `potpis`.

Kanonski bajtovi:

```json
{"v":"opoziv/1","vrsta":"clanstvo","nodeId":"…","publicKey":"…","issuedAt":1760000000,"opozvanoAt":1760000060,"opozvao":"…","potpisnik":"…"}
```

Opoziv poništava potvrdu tog ključa izdanu u trenutku `issuedAt` i sve
starije.

Članstvo smije opozvati ključ mreže i, kad ga je izdao ovlašteni
primatelj, taj primatelj. Ovlast smije opozvati samo ključ mreže.

Oznaka opoziva (`id`) mora biti
`<vrsta>:<publicKey>:<issuedAt>:<prvih 8 bajtova SHA-256 potpisa, heks>`.
Opoziv pod drugom oznakom ne opoziva ništa.

Opoziv putuje kao svaki drugi zapis i ne da se povući: verzija koja ga
briše ne poništava ga. Za razliku od članstva i ovlasti, opoziv se
provjerava već kad stigne: prima se samo onaj kojem oznaka odgovara
sadržaju, a potpis navedenom potpisniku. Smije li taj ključ opozivati,
gleda se pri upotrebi.

### Obnova

Računalo kojem članstvu ostane manje od 30 dana upiše zahtjev za obnovu,
potpisan svojim ključem. Zahtjev putuje kao običan zapis, pa stiže i preko
posrednika. Računalo koje smije primati izda novo članstvo za isti ključ.

Kanonski bajtovi zahtjeva:

```json
{"v":"obnova/1","nodeId":"…","publicKey":"…","network":"…","kad":1760000000,"ovlast":false}
```

### Primanje na daljinu

Kad se dva čovjeka ne mogu naći pred zaslonima, novo računalo izradi
datoteku zahtjeva, a računalo koje prima vrati datoteku potvrde. Umjesto
koda od šest znamenki veže ih **kod za primanje**: 8 znakova iz
`ABCDEFGHJKMNPQRSTUVWXYZ23456789`, koji ljudi prenesu drugim putem.

Zahtjev: `v`, `cvor`, `naziv`, `kljuc`, `izdanje`, `vrijeme`, `sol`,
`dokaz`, `potpis`. Potpis (ključ novog računala) i dokaz pokrivaju JSON
zahtjeva u kojem su `potpis` i `dokaz` prazni.

- Ključ dokaza: scrypt(kod, `<oznaka primanja>` ‖ sol, N = 65536, r = 8,
  p = 1, 32 bajta). Sol je 16 nasumičnih bajtova.
- Dokaz: base64(HMAC-SHA256(ključ dokaza, `<oznaka zahtjeva>|` ‖ bajtovi)).

Potvrda: `v`, `mreza`, `kljuc_mreze`, `clanstvo`, `ovlast`, `izdao`,
`izdano`, `cvorovi`, `sol`, `dokaz`. Dokaz se računa isto, s oznakom
potvrde, nad JSON-om potvrde bez polja `dokaz`, s ključevima po abecedi.

Tri oznake (zahtjeva, potvrde i primanja) daje aplikacija. Granice:
zahtjev 64 KiB, potvrda 1 MiB.

### Kopija ključa mreže

Privatni ključ mreže može se spremiti u datoteku zaštićenu lozinkom.
Datoteka ne putuje mrežom.

Polja: `v` (oznaka kopije, daje je aplikacija), `mreza`, `javni`, `n`,
`sol`, `nonce`, `sifrirano`.

- Ključ: scrypt(lozinka, sol od 16 bajtova, N = `n`, r = 8, p = 1, 32
  bajta). Piše se `n` = 65536, a čita 2 do 1 048 576.
- Šifra: AES-256-GCM, nonce 12 bajtova. Otvoreni tekst je sjeme ključa (32
  bajta). Uz šifru su vezani `v`, `mreza`, `javni` i `n`, svaki u svom
  retku.
- Lozinka ima najmanje 12 znakova, a datoteka najviše 16 KiB.

## 8. Putovi

Isti razgovor ide svakim putem. Put ne ide na žicu: svaka strana ga zna
sama.

### 8.1 Pronalaženje u lokalnoj mreži

UDP. Tko traži, pošalje tekst `<protokol>-discover-v1`. Tko čuje probu
svog protokola, odgovori JSON-om:

| Polje | Značenje |
|---|---|
| `protocol` | ime protokola |
| `deviceId` | ime računala |
| `name` | ime za prikaz |
| `exchangePort` | port razmjene |
| `pairPort` | port uparivanja; samo dok računalo čeka uparivanje |
| `meta` | po želji aplikacije |

Proba se šalje tri puta, u 0, 150 i 400 ms.

Sve u odgovoru je tvrdnja. Odgovor kaže samo gdje pokušati; tko je na toj
adresi, dokazuje tek TLS.

### 8.2 Izravna veza

TCP na port razmjene, TLS iz odjeljka 5, zatim razgovor iz odjeljka 10.

### 8.3 Tunel kroz web poslužitelj

Za računalo do kojeg se izvana može samo HTTPS-om. Klijent otvori
WebSocket na putu `/razmjena/tunel`, s binarnim okvirima. Unutar
WebSocketa ide isti TLS i isti razgovor kao na portu. Vanjski HTTPS štiti
samo put do poslužitelja; povjerenje i dalje daje unutarnji TLS.

### 8.4 WEB sync: izravno preko interneta

Dva računala iza usmjerivača spajaju se izravno, uz pomoć trećeg koje
samo prenosi poruke dogovora (sastajalište).

1. **STUN.** Računalo s jedne UDP utičnice pita dva STUN poslužitelja za
   svoju javnu adresu i po tome zaključi kakav je usmjerivač.
2. **Signal.** Računalo drži vezu sa sastajalištem: WebSocket na putu
   `/razmjena/signal`, unutra TLS 1.3 s ALPN-om `<protokol>-signal/1`.
3. **Poziv, odziv, sinkro.** Preko sastajališta računala razmijene
   potpisane poruke s adresama na kojima ih se može pokušati dobiti.
4. **Udarci.** Oba računala šalju jedno drugome male UDP pakete da otvore
   put kroz usmjerivače.
5. **QUIC.** Kad udarac prođe, računalo s manjim ključem otvori QUIC vezu
   na istoj utičnici. ALPN je `<protokol>-web/1`.

Sastajalište vidi tko koga zove i s kojih adresa, ali ne vidi podatke i ne
može se predstaviti kao član: poruke su potpisane, a QUIC ima svoj TLS.

#### Okvir signala

Svaka poruka signala je okvir: 4 bajta duljine (big-endian), pa toliko
bajtova, najviše 64 KiB. Sadržaj je JSON `{"vrsta": …, "tijelo": …}`.

| `vrsta` | Smjer | `tijelo` |
|---|---|---|
| `prijava` | računalo → sastajalište | inačica, oznaka pokretanja, izdanje |
| `prijavljen` | sastajalište → računalo | potvrda upisa, vrijeme, razmak pulsa u sekundama |
| `odbijeno` | sastajalište → računalo | `kod`, `razlog`, `ponovnoZaSek` |
| `upozorenje` | sastajalište → računalo | `kod` |
| `puls` | oba smjera | `odgovori` |
| `poziv`, `odziv`, `sinkro` | računalo → sastajalište → računalo | potpisana poruka, niže |
| `nema` | sastajalište → računalo | sesija i razlog zašto poruka nije isporučena |

Nepoznata vrsta se zanemaruje.

#### Potpisana poruka

`poziv`, `odziv` i `sinkro` imaju tijelo `{"tijelo": …, "potpis": …}`, oba
base64. Potpis je Ed25519 nad `<protokol>-<vrsta>-v1|` ‖ bajtovi tijela.
Potpisuju se bajtovi kako su stigli, ne ponovno složen JSON.

Tijelo je JSON:

| Polje | Značenje |
|---|---|
| `ver` | 1 |
| `sesija` | 16 nasumičnih bajtova kao 32 heksadecimalna znaka |
| `od`, `za` | javni ključ pošiljatelja i primatelja |
| `sastajaliste` | javni ključ sastajališta preko kojeg poruka ide |
| `izdano` | Unix vrijeme u sekundama |
| `tajna` | nasumični bajtovi; u pozivu i u odzivu |
| `kandidati` | popis `{vrsta, adresa}`: adrese na kojima se pošiljatelj može dobiti |
| `nat` | što pošiljatelj zna o svom usmjerivaču |
| `odluka`, `razlog` | u odzivu: `probaj`, `odbij` ili `iskljuceno`; razlog izostaje kad ga nema |
| `obradaMs` | u odzivu: koliko je primatelj radio |
| `pokusaj`, `rttMs` | u sinkru: redni broj pokušaja (1–3) i izmjereno kašnjenje |
| `vj` | vjerodajnice pošiljatelja; u pozivu i odzivu |

Prazna polja izostaju. Primatelj prihvaća poruku kad: potpis vrijedi,
pošiljatelj je član, `za` je njegov ključ, `sastajaliste` je ključ
njegova sastajališta, `izdano` nije dalje od 10 minuta od njegova sata i
istu poruku nije već vidio.

Sastajalište poruku prosljeđuje netaknutu i odbaci je kad `od` nije ključ
veze s koje je stigla.

#### Udarac

Paket od točno 60 bajtova:

| Bajtovi | Sadržaj |
|---|---|
| 0 | vrsta: `0x10` udarac, `0x11` odgovor |
| 1 | smjer pošiljatelja: 0 ili 1 |
| 2 | inačica: 1 |
| 3 | 0 |
| 4–19 | sesija |
| 20–27 | brojač, big-endian |
| 28–59 | HMAC-SHA256 nad bajtovima 0–27 |

Smjer 0 šalje računalo s manjim javnim ključem. Ključ HMAC-a za jedan
smjer je HKDF-SHA256, bez soli, 32 bajta:

- ulazna tajna: tajna iz poziva ‖ tajna iz odziva (svaka barem 16 bajtova);
- `info`: `<protokol>-udarac-v1` ‖ sesija (16 bajtova) ‖ smjer (1 bajt).

Udarac zato vrijedi samo u toj sesiji i samo u jednom smjeru. Primatelj
pamti zadnja 64 brojača i ponovljen odbacuje. Brojač 0 ne vrijedi.

Odgovara se samo na adresu s koje je stigao valjan udarac, i jednom po
udarcu. Udara se najviše 8 adresa druge strane.

Prvi bajt je odabran da paket na istoj utičnici ne nalikuje ni QUIC-u
(gornja dva bita su 0) ni STUN-u (koji počinje s `0x00` ili `0x01`).

#### QUIC sesija

Do TLS-a dolazi samo adresa s koje je u zadnjih 30 sekundi stigao valjan
udarac ili odgovor. Ključ klijenta mora biti ključ druge strane iz te
pripreme.

Prvi bajt svakog toka kaže čemu tok služi:

| Bajt | Tok |
|---|---|
| `0x00` | kontrolni: pozdrav sa sesijom, ping, najava zatvaranja |
| `0x01` | razgovor iz odjeljka 10 |

Tok s drugim prvim bajtom zatvara se kodom `0x0101`.

Certifikat u ovoj vezi ne nosi vjerodajnice. Članstvo druge strane uzima
se iz potpisanog poziva ili odziva i provjerava na početku svakog toka
razgovora.

### 8.5 Redoslijed putova

Pozivatelj proba putove ovim redom i staje na prvoj vezi koja se
uspostavi:

1. adrese u lokalnoj mreži, usporedno: svaka iduća kreće 250 ms kasnije,
   3 s po adresi;
2. živa WEB sync sesija, ako odgovori na ping;
3. sve ostalo zajedno: javne adrese, privatna VPN mreža i tunel, 20 s po
   adresi.

Cijelo spajanje ima rok 45 s. Jednim putem zove se najviše 8 adresa, jer
zapis o adresama računala može pisati bilo koji član.

Kad nijedan put ne uspije, a obje strane imaju oznaku `web/1`, WEB sync se
priprema u pozadini i razmjena ne čeka na njega.

## 9. Omotnica poruke razgovora

Razgovor je niz JSON objekata, jedan po retku. Svaki je omotnica:

| Polje | Tip | Značenje |
|---|---|---|
| `kind` | tekst | vrsta poruke |
| `reason` | tekst, izostaje kad je prazan | razlog odbijanja, za čovjeka |
| `kod` | cijeli broj, izostaje kad je 0 | kod odbijanja (odjeljak 13) |
| `deviceId` | tekst, izostaje kad je prazan | ime pošiljatelja |
| `payload` | JSON, izostaje kad je prazan | sadržaj poruke |

`deviceId` je obavijest. Identitet je ključ dokazan u TLS-u.

**Nepoznata polja se zanemaruju.** Na tome stoji spojivost starijih i
novijih izdanja. Jedino `payload` verzije putuje dalje netaknut i kad ga
primatelj ne razumije.

**Znakovi `<`, `>` i `&` u tekstu pišu se kao `\u003c`, `\u003e` i
`\u0026`,** kako JSON piše Go. To vrijedi za omotnicu, za kanonske
bajtove potpisa (odjeljak 7) i za sadržaj verzije: računalo koje verziju
šalje ili prosljeđuje zapiše `payload` u tom obliku i kad ga je autor
zadao drukčije. Izvedba zato sadržaj verzije od početka piše tako, inače
isti zapis na dva računala nema iste bajtove. Isto vrijedi za znakove
U+2028 i U+2029, koji se pišu kao `\u2028` i `\u2029`.

Rok je 60 s za slanje i 120 s za primanje jedne poruke.

Najveća primljena poruka ovisi o vrsti koju razgovor čeka:

| Vrsta | Najviše |
|---|---|
| `frontier`, `granica-odbijenih`, `rupe` | 8 MiB |
| `delta` | 64 MiB |
| `zelje` | 1 MiB |
| `sadrzaj` | 128 MiB; 64 KiB kad razgovor ništa nije tražio |
| `done` | 64 KiB |

Veća poruka prekida razgovor.

Odbijenica je poruka vrste `odbijeno` s razlogom (odjeljak 13). Smije
stići umjesto bilo koje poruke. Primatelj je prepoznaje po nepraznom
`reason` u poruci koju nije čekao.

## 10. Razgovor

U svakom koraku pozivatelj prvi šalje, a pozvani prvo prima.

```text
pozivatelj                              pozvani
frontier            ─────────────▶
                    ◀───────────── frontier
granica-odbijenih   ─────────────▶      samo uz oznaku granica-odbijenih/1 na obje strane
                    ◀───────────── granica-odbijenih
rupe                ─────────────▶      samo uz oznaku rupe/1 na obje strane
                    ◀───────────── rupe
delta               ─────────────▶
                    ◀───────────── delta
        (obje strane upišu primljeno)
zelje               ─────────────▶
                    ◀───────────── zelje
sadrzaj             ─────────────▶
                    ◀───────────── sadrzaj
done                ─────────────▶
                    ◀───────────── done
```

1. **Granice.** Svaka strana kaže dokle zna, što želi i što razumije.
2. **Granica odbijenih.** Svaka strana kaže dokle je odbila ono što joj je
   druga strana ranije poslala (odjeljak 14.2).
3. **Rupe.** Svaka strana kaže koje raspone verzija traži (odjeljak 14.3).
4. **Delte.** Obje strane slože deltu prije nego što stigne tuđa. Za svaki
   svoj ključ granice pošiljatelj šalje neprekinut niz verzija iznad tuđe
   granice, najviše 5000 po ključu, samo u kanalima koje druga strana
   želi. Poruka delte ima najviše 32 MiB; kad je veća, reže se s kraja i
   nosi `skraceno`. Prva verzija ide uvijek.
5. **Upis.** Bez poruke. Primatelj odbaci neispravne verzije (odjeljak 11),
   zatim ono što ne želi, i ostalo upiše. Ista verzija primljena dvaput
   upiše se jednom. Verziju veću od najveće dopuštene (odjeljak 18)
   primatelj odbije i zapamti kao odbijenu, a pošiljatelj je ne šalje.
6. **Želje.** Svaka strana pošalje otiske sadržaja koje traži.
7. **Sadržaj.** Svaka strana pošalje od traženoga ono što ima i što druga
   strana smije dobiti. Primatelj upisuje samo ono što je u ovom razgovoru
   sam tražio i čemu otisak odgovara bajtovima.
8. **Kraj.** `done` u oba smjera.

Kad umjesto `zelje` stigne `done`, razgovor je uspješno gotov. Tako
završava izvedba bez sadržaja i pozivatelj koji nije stigao upisati
primljeno.

Poruka koja nije ona koju razgovor čeka je greška razgovora.

Razgovor s istim računalom ponavlja se odmah dok je delta puna ili
skraćena, ali samo dok se stanje pomiče.

## 11. Poruke i polja

### `frontier`

| Polje | Tip | Značenje |
|---|---|---|
| `frontier` | mapa ključ granice → oznaka verzije | dokle pošiljatelj zna |
| `wants` | `{all, rules}` | što pošiljatelj želi; bez polja znači sve |
| `program` | tekst | izdanje aplikacije |
| `gradnja` | tekst | puna oznaka gradnje |
| `mogucnosti` | popis teksta | oznake `ime/N` (odjeljak 12) |
| `vrste` | mapa tekst → cijeli broj | vrsta zapisa → najviša shema koju pošiljatelj razumije |
| `cekaNadogradnju` | cijeli broj | koliko zapisa kod pošiljatelja čeka noviju aplikaciju |
| `uloge` | popis teksta | oznake koje aplikacija javlja o računalu; samo za prikaz |

Sva polja osim `frontier` izostaju kad su prazna. Tipovi polja
`mogucnosti`, `vrste` i `cekaNadogradnju` ne smiju se nikad promijeniti:
drugi tip srušio bi čitanje cijele poruke kod starijeg izdanja.

### `granica-odbijenih`

| Polje | Tip | Značenje |
|---|---|---|
| `granica` | mapa ključ granice → oznaka verzije | najveća verzija koju je pošiljatelj poruke odbio od primatelja |

Šalje se i prazna.

### `rupe`

| Polje | Tip | Značenje |
|---|---|---|
| `trazim` | mapa ključ granice → `{od, do}` | raspon oznaka (od, do] koji pošiljatelj traži |

Prazan `od` znači od početka niza. `~` kao `do` znači bez kraja. Šalje se
i prazna. Najviše 4096 ključeva; ključ do 256 znakova, oznaka do 64.

### `delta`

| Polje | Tip | Značenje |
|---|---|---|
| `versions` | popis verzija | verzije za primatelja |
| `skraceno` | bool, izostaje kad je `false` | delta je skraćena, ima još |
| `tailscale` | popis teksta, izostaje kad je prazan | adrese pošiljatelja u privatnoj VPN mreži, s portom; samo kad razgovor ide tom mrežom |
| `rupe` | mapa ključ → raspon | dio poslanoga za koji pošiljatelj ne jamči da ga ima cijelog; samo uz `rupe/1` |
| `popuna` | mapa ključ → raspon | dio tražene rupe koji je pošiljatelj pokrio; samo uz `rupe/1` |

### `zelje` i `sadrzaj`

| Poruka | Polje | Tip | Značenje |
|---|---|---|---|
| `zelje` | `otisci` | popis teksta | otisci sadržaja koje pošiljatelj traži |
| `sadrzaj` | `stavke` | popis `{otisak, vrsta, kanal, bajtova, podaci}` | sadržaj; `podaci` su base64, `kanal` izostaje kad je prazan |

### `done`

| Polje | Tip | Značenje |
|---|---|---|
| `applied` | cijeli broj | koliko je pošiljatelj upisao; samo obavijest |

### `odbijeno`

Bez `payload`. `reason` i `kod` su u omotnici.

### Verzija

| Polje | Tip | Značenje |
|---|---|---|
| `version_id` | tekst | oznaka verzije, UUIDv7 |
| `entity` | tekst | vrsta zapisa |
| `entity_id` | tekst | oznaka zapisa |
| `node_id` | tekst | autor |
| `supersedes` | tekst | verzija koju je ova zamijenila |
| `archived` | bool | zapis je uklonjen |
| `payload` | JSON | cijeli zapis kako ga vidi aplikacija |
| `created_at` | vrijeme, RFC 3339 | sat autora; samo obavijest, ne za poredak |
| `schema_version` | cijeli broj | shema zapisa |
| `channel` | tekst, izostaje kad je prazan | kanal |

Primatelj ne prima verziju:

- bez `version_id`, `entity` ili `entity_id`;
- čija oznaka nije UUIDv7 u kanonskom obliku: 36 znakova, mala slova,
  crtice na mjestu, inačica 7;
- sa znakom `|` u `node_id` ili `channel`;
- čije je vrijeme u oznaci više od 5 minuta ispred sata primatelja;
- koja nosi ime primatelja kao autora, a vrijeme joj je ispred njegova
  sata.

Neispravna verzija se preskoči, a razgovor ide dalje. Pošiljatelj istim
pravilima ne šalje ono što primatelj ne bi primio.

Verzija je zatvorena: polje koje starije izdanje ne poznaje ono odbaci i
verziju dalje šalje bez njega. Novi podatak o zapisu zato ide u `payload`.

## 12. Oznake mogućnosti

Oznaka je `ime/N`. Ime su mala slova, znamenke i `-`, najviše 32 znaka.
`N` je cijeli broj od 1 naviše, bez vodećih nula.

- Nepoznata ili neispravna oznaka se zanemaruje.
- Računalo bez popisa, ili bez ijedne ispravne oznake na njemu, vrijedi
  kao da je javilo `razmjena/1`.
- Za isto ime vrijedi najviši zajednički `N`. Svaka strana zato navodi
  svaki `N` koji još govori.
- Novo neobavezno polje ne treba oznaku. Nova vrsta poruke ili novo
  značenje smiju se koristiti samo kad obje strane imaju oznaku.
- Oznake ne sadrže ime protokola.

| Oznaka | Što uključuje |
|---|---|
| `razmjena/1` | osnovni razgovor: `frontier`, `delta`, `zelje`, `sadrzaj`, `done` |
| `granica-odbijenih/1` | poruka `granica-odbijenih` iza granica |
| `rupe/1` | poruka `rupe`; polja `rupe` i `popuna` u delti |
| `web/1` | računalo prima WEB sync; javlja je samo dok mu je WEB sync uključen |

Aplikacija smije prijaviti i svoje oznake uz svoje dodatne korake.

Od druge strane pamti se najviše 32 oznake i 1024 vrste zapisa.

## 13. Kodovi odbijanja

Odbijenica je omotnica `{"kind":"odbijeno","reason":…,"kod":…}`. Isti broj
znači isto na svakom putu.

| Kod | Na žici | Kad |
|---|---|---|
| `0x0100` | 256 | greška bez posebnog razloga |
| `0x0101` | 257 | tok na kanalu koji računalo ne poznaje |
| `0x0102` | 258 | sva mjesta za dolazne razmjene su zauzeta |
| `0x0103` | 259 | odbijanje bez točnijeg koda |
| `0x0104` | 260 | druga strana nije član ili je opozvana |
| `0x0105` | 261 | zauzet; ne koristi se i ne daje se drugom razlogu |
| `0x0106` | 262 | pozvani nije stigao upisati primljeno; ostatak razgovora otpada |
| `0x0107` | 263 | veza je stigla putem koji je računalu isključen |

- Popis je stalan. Kod se ne mijenja i ne daje drugom razlogu.
- 0 znači da koda nema.
- Uz kod uvijek ide i razlog.

Certifikat s drugim imenom protokola nema kod: veza se zatvara bez poruke.

## 14. Granice

### 14.1 Granica knjige

Granica je, za svaki par autora i kanala, najveća oznaka verzije koju
računalo ima. U nju ulaze samo verzije koje bi razmjena danas primila.

Granica ne gleda vrstu zapisa. Zato verzija zapisa koji ovo računalo ne
razumije putuje dalje i čeka noviju aplikaciju.

Pošiljatelj za svaki ključ šalje neprekinut niz iznad granice primatelja, a
rez delte reže samo kraj niza. Granica primatelja tako ne preskače ništa.

Najveća verzija po ključu ostaje u knjizi i nakon čišćenja povijesti. Bez
nje bi je druga strana slala natrag svakim razgovorom.

### 14.2 Granica odbijenih

Računalo smije odbiti verziju koju ne želi držati. Tada mu se granica
knjige ne pomakne, pa bi mu je pošiljatelj slao svaki put.

Zato računalo za svakog pošiljatelja, po njegovu ključu, pamti najveću
oznaku koju je od njega odbilo. Uz oznaku `granica-odbijenih/1` to mu
javi, a pošiljatelj deltu slaže od većega od dvoga.

Granica odbijenih je samo između dva računala. Ne ide u knjigu ni
trećima. Pamti se u memoriji, najdulje 24 sata, i zaboravlja se kad se
promijeni ono što računalo želi.

### 14.3 Rupe u nizu

Računalo koje nešto odbije drži niz s rupom. Kad taj niz proslijedi
trećem, granica trećeg prijeđe preko rupe i odbijeno do njega više ne
stigne.

Zato svako računalo, po tuđem ključu, trajno vodi dva raspona: što je
samo odbilo (za to drugima ne jamči) i što možda nema, a treba.

Uz oznaku `rupe/1`:

- svaka strana u poruci `rupe` javi što traži;
- pošiljatelj koji ima početak tuđe rupe pošalje ključ od početka rupe, na
  kraju delte, i to javi u `popuna`;
- uz deltu javi u `rupe` dio poslanoga za koji ne jamči.

Vlastiti ključ nikad nema rupu.

## 15. Kanali i želje

Kanal je tekst bez znaka `|`. Prazan kanal drže svi članovi. Što kanal
znači, zna aplikacija.

Što računalo želi, javlja u `wants` svake granice:

- `{"all": true}`: sve kanale;
- inače `rules`: pravila koja tumači aplikacija.

Filtrira se na obje strane. Pošiljatelj ne šalje kanal koji druga strana
ne želi, a primatelj ne upisuje kanal koji sam ne želi. Kanal koji
računalo ne drži inače bi mu se vraćao svakim razgovorom.

Želje su lokalne. Ne idu u knjigu, nego u svaku granicu.

## 16. Sadržaj po otisku

Veće datoteke ne putuju u verziji. Verzija nosi otisak, a bajtovi idu
zasebno, u koraku sadržaja.

- Ime sadržaja je njegov otisak.
- Što se traži, odlučuje primatelj, ne pošiljatelj.
- Po razgovoru se traži i šalje najviše 200 stavki i 48 MiB. Jedna stavka
  veća od toga smije sama. Stavka veća od 64 MiB ne šalje se.
- Primatelj upisuje samo ono čemu otisak odgovara bajtovima i što je u
  tom razgovoru sam tražio. Vrstu sadržaja uzima iz vlastite želje, a od
  pošiljatelja samo kad je želja nema.

## 17. Paket za prijenos datotekom

Zapisi se mogu prenijeti i datotekom, bez mreže. Paket je ZIP s četiri
vrste stavki:

| Stavka | Sadržaj |
|---|---|
| `manifest.json` | što je u paketu, tko ga je izdao, potpis |
| `zapisi.jsonl` | verzije, jedna po retku |
| `sadrzaji.json` | popis sadržaja: otisak, vrsta, veličina, kanal, je li uključen |
| `sadrzaj/<otisak>` | bajtovi uključenog sadržaja |

Paket potpisuje ključ računala koje ga je izdalo. Uvoz odbija paket novije
inačice, s krivim otiskom ili potpisom, od izdavača koji nije član iste
mreže, starije izdanje istog izdavača i isto izdanje s drugim sadržajem.
Zapise uvoz uzima kao razmjena: samo ono što računalo želi.

Nepoznata stavka u paketu je greška. Novi dio paketa zato uvijek traži
novu inačicu.

### Manifest i potpis

Polja manifesta: `inacica`, `obuhvat`, `kanali`, `izdanje`, `prethodno`,
`izdao`, `nastalo`, `otisak`, `zapisa`, `sadrzaja`, `ukljuceno`, `potpis`,
`rupe`. `potpis` je `{"kljuc": …, "potpis": …}`, oba base64.

Potpisuje se tekst, jedan redak po podatku: ime, tabulator, vrijednost,
novi red. Redom:

```text
inacica     <broj>
obuhvat     <tekst obuhvata>
kanali      <kanali poredani po abecedi, odvojeni zarezom>
izdanje     <broj>
prethodno   <otisak prethodnog izdanja; redak postoji i kad je prazan>
izdao       <ime računala>
otisak      <otisak izdanja>
zapisa      <broj>
sadrzaja    <broj>
rupe        <samo kad paket nosi rupe>
```

Redak `rupe` za svaki ključ po abecedi nosi `"ključ"="od","do";`. Paket
bez rupa tog retka nema, pa mu je potpis isti kao u starijoj inačici.

`nastalo`, `ukljuceno` i sam potpis nisu potpisani.

**Obuhvat** je u potpisu samo tekst. Što taj tekst znači i kako ga složiti,
zna aplikacija; biblioteka ga uspoređuje kao cjelinu. Po njemu uvoz
prepoznaje novije i starije izdanje istog paketa.

**Otisak izdanja** je SHA-256 nad bajtovima `zapisi.jsonl`, iza kojih za
svaki sadržaj, poredano po otisku, ide redak
`<otisak> <vrsta> <bajtova>` s novim redom. Bajtovi sadržaja ne ulaze u
otisak, pa su paket samo s popisom i paket sa svim sadržajem isto izdanje.

Granice pri čitanju: manifest 1 MiB, zapisi 512 MiB, popis sadržaja
64 MiB, jedan sadržaj 256 MiB, najviše 262 144 stavke ZIP-a.

## 18. Ograničenja

| Što | Koliko |
|---|---|
| verzija po ključu granice u jednoj delti | 5000 |
| poruka delte pri slanju | 32 MiB; prva verzija ide uvijek |
| najveća verzija | granica delte manje 1 MiB |
| sadržaj po razgovoru | 200 stavki, 48 MiB; pojedini do 64 MiB |
| traženih rupa po poruci | 4096 ključeva |
| vrijeme u oznaci primljene verzije | najviše 5 min ispred sata |
| vjerodajnice u certifikatu | 16 KiB |
| okvir signala | 64 KiB |
| ime protokola | 32 znaka |
| dolazne razmjene odjednom | 4 |
| odlazne razmjene odjednom | 4 |
| rukovanja odjednom | 32; 4 s jedne adrese, 8 s jedne javne mreže |
| rok poruke | slanje 60 s, primanje 120 s |
| pričuva isteklog članstva | 30 dana |
| granica odbijenih | 24 h, samo u memoriji |
| razmak automatske razmjene | prvi put nakon 30 s, zatim svakih 5 min |

Brojevi su iz koda. Izvedba ne smije slati više od ovoga, a primati mora
barem onoliko koliko druga strana smije poslati: granice primanja po vrsti
poruke su u odjeljku 9. Izvedba s manjim granicama primanja odbit će
ispravne poruke.

## 19. Kako se protokol mijenja

Starije izdanje ne smije zapeti ni pasti.

1. Novo neobavezno polje poruke ne treba oznaku. Izostaje kad je prazno,
   da poruka bez njega ostane bajt po bajt ista.
2. Postojeće polje se ne mijenja: ni ime, ni tip, ni značenje. Novi oblik
   ide pod novo ime.
3. Nova vrsta poruke ili novo značenje traži novu oznaku mogućnosti i
   koristi se samo kad je obje strane imaju.
4. Prva poruka razgovora ostaje `frontier`.
5. Novi kod odbijanja dobiva novi broj. Stari se ne mijenjaju.
6. Kanonski bajtovi potpisa se ne mijenjaju. Novi oblik dobiva novu
   oznaku inačice, a stari se i dalje čita.
7. Novi podatak o zapisu ide u `payload` verzije, ne u novu kolonu
   verzije.

## 20. Što u ovom opisu još nije opće

Kod iz kojeg syncnet nastaje danas služi jednoj aplikaciji. Ovo su mjesta
gdje se to vidi na žici. Rješavaju se prije objave:

- Oznake formata nose ime te aplikacije i stalne su u kodu. U syncnetu ih
  daje aplikacija.
- Pravila u `wants.rules` imaju oblik koji razumije samo ta aplikacija, a
  tumači ih pošiljatelj. U syncnetu pravilo daje aplikacija.
- `uloge` u granici danas imaju dvije stalne vrijednosti.
- Polje `tailscale` u delti nosi ime jednog proizvoda. Podrška za privatnu
  VPN mrežu u syncnetu je dodatak koji aplikacija može, ali ne mora dati.
- Jedna oznaka mogućnosti i jedna vrsta stavke u `sadrzaj` služe samo toj
  aplikaciji. U syncnetu ih prijavljuje aplikacija.
- Putovi `/razmjena/tunel` i `/razmjena/signal`, imena polja i vrste
  poruka su na hrvatskom. Dio su žice i ne mijenjaju se bez nove oznake.
