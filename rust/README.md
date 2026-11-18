# syncnet u Rustu

Opća biblioteka u Rustu: Ed25519 identitet i TLS 1.3 certifikati, SAS uparivanje,
ovlasti/članstvo/opozivi usklađeni s goCOP-ovim vektorima žice, pronalaženje u
lokalnoj mreži, STUN, UDP probijanje, signal, okvir poruke, kodek inačice 1
razgovora i potpisani paket `bundle_v2`.

```sh
cargo test
```

## Što još ostaje za dovršiti

- oznaku vjerodajnica mora moći zadati aplikacija neovisno o imenu protokola
  (goCOP je drži stalnom i uz drugo ime protokola);
- zadani port pronalaženja ne smije biti vezan uz jednu aplikaciju;
- korisničke rečenice u greškama treba u potpunosti svesti na kodove kako bi
  tekstove pisala aplikacija;
- testne vektore čitati iz zajedničke mape `vektori/` umjesto vlastite kopije
  (`testdata/go-vectors.json`);
- logika razgovora inačice 1 i opća knjiga dolaze u sljedećoj fazi (trenutno su
  u biblioteci kodek i tipovi poruka inačice 1, a prijedlog inačice 2 opisan je
  u [docs/PROTOKOL-V2.md](../docs/PROTOKOL-V2.md)).
