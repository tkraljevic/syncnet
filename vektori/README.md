# Ispitni vektori

Vektor je par „ovaj ulaz daje točno ove bajtove”. Druga izvedba protokola
koja iz istog ulaza dobije iste bajtove govori istu žicu.

Vektore je izradio kod programa iz kojeg syncnet nastaje, 18. 11. 2026.
Dopunjeni su 26. 11. 2026. iz istog programa: potpis verzije, paket za
prijenos datotekom i primanje na daljinu. Stari vektori pritom nisu
promijenjeni. Isto vrijedi za dvije dopune od 28. 11. 2026.: dva koda
uparivanja za druge brojeve pozvanog (`uparivanje.kodSNulom` i
`uparivanje.kodSNajvisimBitom`) te rubovi potpisa verzije i još dvije
potpisane verzije (`potpisVerzije`).
Ed25519 potpis i zapis JSON-a za isti ulaz daju isti izlaz, pa se vektori
izrađuju ponovljivo: izrađeni su dvaput i oba puta su bili isti.

## Stalni ulaz

| Što | Vrijednost |
|---|---|
| Sjeme ključa A, B i mreže | 32 bajta `0x01`, `0x02`, `0x10` |
| Vrijeme | `1760000000` (9. 10. 2025. 08:53:20 UTC) |
| Sesija | `00112233445566778899aabbccddeeff` |
| Tajna poziva, tajna odziva | 32 bajta `0xAA`, 32 bajta `0xBB` |
| Broj pozivatelja, broj pozvanog | bajtovi `0x00…0x1f`, `0x80…0x9f` |
| Broj pozvanog za `kodSNulom` | bajt `0x80` pa 31 bajt `0x00` |
| Broj pozvanog za `kodSNajvisimBitom` | bajt `0x80`, 30 bajtova `0x00`, bajt `0x03` |
| Ime protokola | `gocop` |
| Oznaka vjerodajnica | `gocop:vjerodajnice:` |

Ime protokola i oznaku vjerodajnica daje aplikacija. Ovdje su vrijednosti
programa u kojem je protokol nastao. Druga aplikacija ima svoje, pa će
dobiti druge bajtove svuda gdje ime ili oznaka ulaze u izračun.

Imena računala (`admin-1`, `racunalo-b`), zapis (`biljeske`) i kanal
(`primjer/7/2026`) su izmišljeni. Izmišljena je i osoba u vektoru potpisa
verzije. Vrste zapisa `users` i `readings` u tom vektoru i kanal
`ocitanja/16/2026` imena su iz programa u kojem je protokol nastao; druga
aplikacija ima svoja.

Primanje na daljinu ima još dva stalna ulaza: sol od 16 bajtova `0xCC` i
kod `7KQ4-M2XD`.

## vektori-zice.json

- ime certifikata (CN) i URI s vjerodajnicama;
- ALPN za signal, WEB sync i probu;
- tekst probe pronalaženja i odgovor na nju;
- uparivanje: `Hello`, obveza, poruke obveze i broja, kod od šest
  znamenki, `Confirm`. Uz to dva koda za druge brojeve pozvanog (vidi
  stalni ulaz, polje `brojSlusalice`). `kodSNulom` počinje nulom
  (`020062`): izvedba koja kod piše bez vodećih nula na njemu padne.
  `kodSNajvisimBitom` (`562166`) ima sažetak koji počinje bajtom `0xc5`:
  izvedba koja prva četiri bajta čita kao broj s predznakom na njemu
  padne;
- kanonski bajtovi, potpis i cijeli zapis za ovlast, članstvo potpisano
  ključem mreže, članstvo potpisano od ovlaštenog primatelja i opoziv;
  oznaka opoziva;
- omotnica poruke razgovora i odbijenica, s novim retkom na kraju;
- kodovi odbijanja, oznake mogućnosti i dogovor s računalom bez oznaka
  (popis oznaka nosi i jednu oznaku samog programa, `dijelovi-karte/1`;
  u syncnetu će takve oznake prijavljivati aplikacija). Među oznakama je
  od 26. 11. 2026. i `potpis-verzije/1`;
- signal: prefiks potpisa, tijelo poziva, potpis, poruka, okvir od 4
  bajta duljine, okvir pulsa;
- udarac od 60 bajtova za oba smjera: smjer, ključ slanja, udarac i
  odgovor s brojačem 7;
- `posebniZnakovi`: ovlast, članstvo i odbijenica s imenom `a<b>&c`, te
  odbijenica s razlogom koji nosi U+2028 i U+2029;
- `potpisVerzije`: verzija iz knjige koju potpiše njezin autor, računalo
  A. Za svaku verziju tu su podaci kako stoje u knjizi (`ulaz`), sadržaj
  kako ide žicom (`oblikSadrzaja`), njegov SHA-256 (`sadrzaj`), bajtovi
  koji se potpisuju, ključ autora i potpis. Verzije su:
  - `obicna`;
  - `posebniZnakovi`: sadržaj s razmacima, sa znakovima `<`, `>` i `&` i
    s U+2028, vrijeme s dijelovima sekunde i druge vrijednosti ostalih
    polja;
  - `sadrzajSBrojevimaIBijegovima`: sadržaj s razmacima, s brojevima
    `1.0` i `1e2` i s bijegovima `\u0041`, `\/` i `\u003C` (veliko C). U
    obliku sadržaja sve to ostaje kako je napisano. Izvedba koja broj
    zapiše drukčije ili bijeg razriješi dobije drugi sažetak i drugi
    potpis;
  - `razdjelnikUPoljima`: U+2028 u `entity_id` i u kanalu. U bajtovima
    koji se potpisuju piše se kao `\u2028`.

  Uz njih je `rubovi`: tablica nad verzijom `obicna`. Svaki redak ima
  `opis`, `potpis` i `kljuc_autora` kako stoje uz verziju i `ishod`:
  `nepotpisana` (oba polja prazna), `kriv` ili `vrijedi`. Ishod je izračunao
  program iz kojeg syncnet nastaje, svojom provjerom potpisa verzije.
  Redovi pokrivaju samo jedno od dvaju polja, prazno polje uz drugo s
  razmakom ili novim retkom, ključ i potpis s razmakom ili tabom ispred ili
  iza, s novim retkom (`\n` ili `\r\n`) iza, u sredini ili u dopuni, bez
  dopune i s viškom dopune, s viškom bitova u zadnjem znaku, u abecedi za
  URL, prekratke i predugačke. Uz to ključ potpisan nad drugim zapisom
  istih bajtova (redovi `_stari_potpis`), ključ od 32 bajta koji nije
  točka krivulje, točku identiteta u tri zapisa, potpis s nesvedenim `s`
  (`s + L`) i potpis s postavljenim najvišim bitom.

## vektori-razgovora.json

Poruke razgovora kako idu žicom, svaka u omotnici i s novim retkom na
kraju: `frontier` (s oznakama mogućnosti i bez njih), `granica-odbijenih`,
`rupe`, `delta` (puna i prazna), `zelje`, `sadrzaj` i `done`. Uz njih jedna
verzija i vjerodajnice računala A, iste koje vektori žice stavljaju u
certifikat, delta s verzijom čiji sadržaj nosi `<`, `>` i `&`, te
`sadrzajBezKanala`: stavka sadržaja u zajedničkom kanalu, u kojoj polje
`kanal` izostaje.

Od 26. 11. 2026. tu su i:

- `deltaSPotpisom`: delta s verzijom koja nosi potpis autora (`potpis` i
  `kljuc_autora`), kako ide računalu s oznakom `potpis-verzije/1`. Potpis
  pokriva oblik iz vektora `potpisVerzije`;
- `cop`: dijelovi paketa za prijenos datotekom koji se potpisuju ili
  otiskuju: zapisi, popis sadržaja, otisak izdanja, kanonski zapis
  manifesta, potpis ključem A i manifest. Sve to dvaput: za paket bez rupa
  (inačica 3) i s rupama (inačica 4);
- `primanje`: primanje novog računala na daljinu: kod koji čovjek prepiše,
  ključ dokaza, zahtjev novog računala (bajtovi, dokaz i potpis ključem B)
  i potvrda primatelja. Ključ dokaza je scrypt (N = 2^16, r = 8, p = 1) nad
  kodom bez crtice i soli, s oznakom `gocop-primanje/1|`.

## Što izvedba u Rustu iz ovoga ne dobije

Rust provjerava sve vektore koje može izraditi. Ostalo je popisano
poimence, s razlogom, u `rust/src/wire/vectors.rs`. Danas su to: vanjska
poruka signala i puls, dogovor oznaka mogućnosti, paket za prijenos
datotekom i primanje na daljinu.

Svi redovi tablice rubova potpisa verzije u Rustu daju ishod iz Goa.

## Znakovi <, > i &

U JSON-u se znakovi `<`, `>` i `&` u tekstu pišu kao `\u003c`, `\u003e` i
`\u0026`. Vektori to pokazuju na tri mjesta:

- u kanonskim bajtovima koji se potpisuju: ime `a<b>&c` potpisuje se kao
  `a\u003cb\u003e\u0026c`;
- u omotnici poruke (razlog odbijenice);
- u sadržaju verzije: `sadrzajSPosebnimZnakovima` je sadržaj kako ga je
  zadao autor, a `deltaSPosebnimZnakovima` ista verzija kako ide žicom.

Izvedba koja te znakove piše doslovno dobije druge bajtove, pa joj potpis
ne vrijedi za ime koje ih sadrži.

Isto vrijedi za U+2028 i U+2029, koji se pišu kao `\u2028` i `\u2029`.

## Što vektori ne pokrivaju

STUN, QUIC sesiju i njezin kontrolni kanal, poruke `odziv` i `sinkro`,
prijavu kod sastajališta i kopiju ključa mreže. Cijeli certifikat nije
vektor, jer mu serijski broj i rok ovise o satu.

Kod potpisa verzije vektori pokazuju bajtove i ishod same provjere
potpisa. Ne pokrivaju potpisan redak paketa ni odluke primatelja koje
ovise o knjizi i članstvima: ključ koji nije vezan uz `node_id`, članstvo
koje stiže u istoj delti, strože pravilo za nepotpisanu verziju od
računala s oznakom `potpis-verzije/1` i dopunu.
