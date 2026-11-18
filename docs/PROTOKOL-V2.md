# Ugovor razgovora — inačica 2 (`<protokol>-razmjena/2`)

Ovaj dokument opisuje prijedlog **inačice 2** razgovora za razmjenu sinkronizacije. Dok ne bude usuglašen i prihvaćen u zajednički ugovor, goCOP i postojeća mreža koriste isključivo inačicu 1 iz [PROTOKOL.md](PROTOKOL.md).

## 1. Pregovaranje inačice preko ALPN-a

- Klijent pri uspostavi TLS 1.3 veze nudi ALPN `<protokol>-razmjena/2`.
- Poslužitelj na vratima razmjene oglašava `<protokol>-razmjena/2`, ali **mora prihvatiti i vezu bez ALPN-a** (`alpn_protocol() == None`).
- **Veza bez dogovorenog ALPN-a uvijek je inačica 1** (JSON po retku iz `PROTOKOL.md`).
- **Veza s dogovorenim `<protokol>-razmjena/2` koristi inačicu 2** opisanu u nastavku.
- Uparivanje ima samo inačicu 1 (JSON po retku kad ALPN nije dogovoren); `<protokol>-pair/1` smije biti samo ponuda, nikad uvjet. Uparivanje i razmjena uvijek su na odvojenim vratima.

## 2. Kadriranje i zajednička omotnica

- Svaka poruka u inačici 2 šalje se kao okvir: **4 bajta duljine (big-endian `u32`) + UTF-8 JSON omotnica**.
- Omotnica je ista kao u inačici 1:
  - `kind` (`string`) — vrsta poruke,
  - `deviceId` (`string`, opcionalno) — pošiljatelj,
  - `payload` (`json`, izostavljeno kod `odbijeno`),
  - `reason` (`string`, samo kod `odbijeno`),
  - `kod` (`u64`, samo kod `odbijeno`).
- Najveća dopuštena veličina okvira provjerava se **po vrsti poruke** koju korak razgovora očekuje:
  - `hello`: 64 KiB
  - `request`: 128 KiB
  - `page`: 2 MiB
  - `zelje`: 64 KiB
  - `sadrzaj`: 2 MiB
  - `done`: 16 KiB
  - ukupna gornja granica omotnice: 4 MiB.

## 3. Tijek i vrste poruka (straničenje)

1. **`hello`**: obje strane razmjenjuju `protocol`, `deviceId`, `name`, `version`, `capabilities` (mogućnosti), `schema_kinds` i trenutni `frontier` (karta kanal/čvor → zadnji `version_id`).
2. **`request`**: strana koja traži podatke šalje zahtjev s granicom (`frontier`), željenim kanalima, traženim rasponima rupa (`holes`) i ograničenjem veličine stranice.
3. **`page`**: pošiljatelj šalje jednu stranicu potpisanih verzija, oznaku `has_more`, ažurirani `frontier` i `holes` dok ne isporuči sve stranice.
4. **`zelje` / `sadrzaj`**: po potrebi razmjena binarnog sadržaja po otisku (`SHA-256`).
5. **`done`** ili **`odbijeno`**: završetak kruga razmjene s brojem primijenjenih zapisa (`applied`) ili odbijenica bez `payload` polja.
