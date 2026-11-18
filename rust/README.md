# syncnet u Rustu

Izvedba u Rustu: ključevi i certifikati, uparivanje uz kod, TLS, članstvo
i ovlasti, pronalaženje u lokalnoj mreži, STUN, probijanje, signal, okvir
poruke, razgovor i potpisani paket.

Premještena je ovamo iz programa List2Cart, koji je i dalje koristi.

```sh
cargo test
```

## Što još nije opće

Kod je pisan za jednu aplikaciju i to se još vidi:

- oznaka vjerodajnica i ALPN-i nose ime te aplikacije kao stalne
  konstante, iako se ime protokola inače zadaje;
- potpis verzije i potpis paketa imaju prefiks s njezinim imenom;
- model dijeljenja (`ListGrant`, uloge članova) je njezin;
- zadani port pronalaženja i zadano ime uređaja su njezini.

Razgovor ima vlastite poruke i ne odgovara onome u
[opisu protokola](../docs/PROTOKOL.md).
