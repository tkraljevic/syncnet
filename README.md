# syncnet

syncnet će biti biblioteka za razmjenu podataka među računalima bez
središnjeg poslužitelja. Računala se uparuju uz kod koji potvrde dva
čovjeka, drže istu knjigu izmjena i u razgovoru jedno drugome daju ono što
ono još nema. Namijenjena je aplikacijama koje podatke drže u SQLiteu.

## Stanje

Ovo je priprema, a ne biblioteka. Koda ovdje još nema, a repozitorij je
privatan dok se syncnet ne dovrši.

Kad kod dođe, za njega će vrijediti ovo:

- alfa je;
- namijenjen je malim skupinama računala čiji si vlasnici vjeruju;
- vanjski sigurnosni pregled nije napravljen.

## Što je ovdje

- [docs/PROTOKOL.md](docs/PROTOKOL.md): nacrt opisa protokola. Kaže što
  putuje među računalima, kojim redom i u kojem obliku.
- [vektori](vektori/README.md): ispitni vektori. Druga izvedba protokola
  koja iz istog ulaza dobije iste bajtove govori istu žicu.

## Odakle

Protokol je nastao u programu
[goCOP](https://github.com/tkraljevic/goCOP), gdje i danas radi. syncnet
ga izdvaja u biblioteku koju može koristiti bilo koja aplikacija. Opis i
vektori ovdje pokazuju žicu kakva je danas u tom programu.

## Licenca

MIT. Tekst je u datoteci [LICENSE](LICENSE).

Dijelovi ovog projekta razvijeni su uz pomoć alata umjetne inteligencije.
