# Ispitni vektori

Vektor je par „ovaj ulaz daje točno ove bajtove”. Druga izvedba protokola
koja iz istog ulaza dobije iste bajtove govori istu žicu.

Vektore je izradio kod programa iz kojeg syncnet nastaje, 18. 11. 2026.
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
| Ime protokola | `gocop` |
| Oznaka vjerodajnica | `gocop:vjerodajnice:` |

Ime protokola i oznaku vjerodajnica daje aplikacija. Ovdje su vrijednosti
programa u kojem je protokol nastao. Druga aplikacija ima svoje, pa će
dobiti druge bajtove svuda gdje ime ili oznaka ulaze u izračun.

Imena računala (`admin-1`, `racunalo-b`), zapis (`biljeske`) i kanal
(`primjer/7/2026`) su izmišljeni.

## vektori-zice.json

- ime certifikata (CN) i URI s vjerodajnicama;
- ALPN za signal, WEB sync i probu;
- tekst probe pronalaženja i odgovor na nju;
- uparivanje: `Hello`, obveza, poruke obveze i broja, kod od šest
  znamenki, `Confirm`;
- kanonski bajtovi, potpis i cijeli zapis za ovlast, članstvo potpisano
  ključem mreže, članstvo potpisano od ovlaštenog primatelja i opoziv;
  oznaka opoziva;
- omotnica poruke razgovora i odbijenica, s novim retkom na kraju;
- kodovi odbijanja, oznake mogućnosti i dogovor s računalom bez oznaka
  (popis oznaka nosi i jednu oznaku samog programa, `dijelovi-karte/1`;
  u syncnetu će takve oznake prijavljivati aplikacija);
- signal: prefiks potpisa, tijelo poziva, potpis, poruka, okvir od 4
  bajta duljine, okvir pulsa;
- udarac od 60 bajtova za oba smjera: smjer, ključ slanja, udarac i
  odgovor s brojačem 7.

## vektori-razgovora.json

Poruke razgovora kako idu žicom, svaka u omotnici i s novim retkom na
kraju: `frontier` (s oznakama mogućnosti i bez njih), `granica-odbijenih`,
`rupe`, `delta` (puna i prazna), `zelje`, `sadrzaj` i `done`. Uz njih jedna
verzija i vjerodajnice računala A, iste koje vektori žice stavljaju u
certifikat.

## Što vektori ne pokrivaju

STUN, QUIC sesiju i njezin kontrolni kanal, poruke `odziv` i `sinkro`,
prijavu kod sastajališta, zahtjev i potvrdu primanja na daljinu, kopiju
ključa mreže i paket za prijenos datotekom. Cijeli certifikat nije vektor,
jer mu serijski broj i rok ovise o satu.
