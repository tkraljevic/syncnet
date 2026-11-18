# Ugovor razgovora — inačica 2 (`<protokol>-razmjena/2`)

> **Status: SKICA.** Ovaj dokument je radna skica inačice 2 prema trenutačnom kodu u Rustu i List2Cartu te još nije usuglašen u zajednički ugovor. Dok nije usklađen, goCOP i postojeća mreža koriste isključivo inačicu 1 iz [PROTOKOL.md](PROTOKOL.md).

## 1. Pregovaranje inačice preko ALPN-a

- Klijent pri uspostavi TLS 1.3 veze nudi ALPN `<protokol>-razmjena/2`.
- Poslužitelj na vratima razmjene oglašava `<protokol>-razmjena/2`, ali **mora prihvatiti i vezu bez ALPN-a** (`alpn_protocol() == None`).
- **Veza bez dogovorenog ALPN-a uvijek je inačica 1** (JSON po retku iz `PROTOKOL.md`).
- **Veza s dogovorenim `<protokol>-razmjena/2` koristi inačicu 2** opisanu u nastavku.
- Uparivanje ima samo inačicu 1 (JSON po retku kad ALPN nije dogovoren); `<protokol>-pair/1` smije biti samo ponuda, nikad uvjet. Uparivanje i razmjena uvijek su na odvojenim vratima.

## 2. Kadriranje i zajednička omotnica

- Svaka poruka u inačici 2 šalje se kao okvir: **4 bajta duljine (big-endian `u32`) + UTF-8 JSON omotnica**.
- Omotnica je ista kao u inačici 1, s redoslijedom polja:
  - `kind` (`string`) — vrsta poruke,
  - `reason` (`string`, samo kod `odbijeno`),
  - `kod` (`u64`, samo kod `odbijeno`),
  - `deviceId` (`string`, opcionalno) — pošiljatelj,
  - `payload` (`json`, izostavljeno kod `odbijeno`).
- Najveća dopuštena veličina okvira provjerava se **po vrsti poruke** koju korak razgovora očekuje:
  - `hello`: 64 KiB
  - `request`: 128 KiB
  - `page`: 2 MiB
  - `zelje`: 64 KiB
  - `sadrzaj`: 2 MiB
  - `done`: 16 KiB
  - ukupna gornja granica omotnice: 4 MiB.

## 3. Tijek i vrste poruka (skica prema kodu)

1. **`hello`**: obje strane razmjenjuju `protocol`, `program`, `gradnja`, `mogucnosti` i `vrste` (inačice sheme po entitetima).
2. **`request`**: potpisani `SyncRequest` iz List2Carta (zahtjev s `frontier`, traženim kanalima/rupama i potpisom pošiljatelja).
3. **`page`**: pošiljatelj šalje stranicu (`ProtectedBundleV2` / delta ili snapshot stranica) dok ne isporuči sve stranice.
4. **`zelje` / `sadrzaj`**: po potrebi razmjena binarnog sadržaja po otisku (`SHA-256`).
5. **`done`** ili **`odbijeno`**: završetak kruga razmjene s brojem primijenjenih zapisa (`applied`) ili odbijenica bez `payload` polja.
