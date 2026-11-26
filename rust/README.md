# syncnet u Rustu

Opća biblioteka u Rustu: Ed25519 identitet i TLS 1.3 certifikati, SAS uparivanje,
ovlasti/članstvo/opozivi usklađeni s goCOP-ovim vektorima žice, pronalaženje u
lokalnoj mreži, STUN, UDP probijanje, signal, okvir poruke, kodek inačice 1
razgovora i potpisani paket `bundle_v2`.

```sh
cargo test
```

Testovi čitaju zajedničke vektore iz mape [vektori](../vektori/README.md),
pod imenom protokola koje je u njima. Što Rust iz tih vektora danas ne može
dobiti, popisano je poimence u `src/wire/vectors.rs` (`DIFFERENCES` i
`DIFFERENCES_CONVERSATION`): vanjska poruka signala, puls, dogovor oznaka
mogućnosti, potpis verzije, paket za prijenos datotekom i primanje na
daljinu.

## Što još ostaje za dovršiti

- potpis verzije uskladiti s Goom: Rust danas potpisuje
  `<protokol>-ver-v1|[…]`, a Go `<protokol>-verzija-v1|{…}` sa sažetkom
  sadržaja, pa jedna izvedba drugoj ne može provjeriti potpis;
- oznaku vjerodajnica mora moći zadati aplikacija neovisno o imenu protokola
  (goCOP je drži stalnom i uz drugo ime protokola);
- zadani port pronalaženja ne smije biti vezan uz jednu aplikaciju;
- korisničke rečenice u greškama treba u potpunosti svesti na kodove kako bi
  tekstove pisala aplikacija;
- logika razgovora inačice 1 i opća knjiga dolaze u sljedećoj fazi (trenutno su
  u biblioteci kodek i tipovi poruka inačice 1, a prijedlog inačice 2 opisan je
  u [docs/PROTOKOL-V2.md](../docs/PROTOKOL-V2.md)).
