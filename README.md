# syncnet

> **Još nije za upotrebu. U intenzivnom je razvoju.**
> Ovo nije biblioteka koju danas možete ugraditi u svoj program. Sučelja,
> protokol i raspored repozitorija mijenjaju se bez najave, a izdanja nema.
>
> **Not usable yet. Under heavy development.** Nothing here is stable and
> there are no releases.

syncnet će biti biblioteka za razmjenu podataka među računalima bez
središnjeg poslužitelja. Računala se uparuju uz kod koji potvrde dva
čovjeka, drže istu knjigu izmjena i u razgovoru jedno drugome daju ono što
ono još nema. Namijenjena je aplikacijama koje podatke drže u SQLiteu.

## Stanje

Ovo je priprema, a ne gotova biblioteka. Što treba znati prije nego što
išta odavde uzmete:

- ništa nije stabilno i ništa nije izdano;
- vanjski sigurnosni pregled nije napravljen, pa se na ovaj kod ne
  oslanjajte za ništa što mora biti sigurno;
- kad biblioteka bude gotova, bit će namijenjena malim skupinama računala
  čiji si vlasnici vjeruju.

## Što je ovdje

| Mapa | Što je u njoj |
|---|---|
| [docs](docs/PROTOKOL.md) | Nacrt opisa protokola: što putuje među računalima, kojim redom i u kojem obliku. |
| [vektori](vektori/README.md) | Ispitni vektori. Izvedba koja iz istog ulaza dobije iste bajtove govori istu žicu. |
| [rust](rust/README.md) | Izvedba u Rustu. |
| `go` | Izvedba u Gou. Još je nema. |

Izvedbe su odvojene: svaka je u svojoj mapi i gradi se zasebno. Opis
protokola i vektori su zajednički.

Dvije izvedbe danas ne govore isti razgovor. Temelji su im isti (ključevi,
uparivanje, članstvo, signal, probijanje), ali izvedba u Rustu ima vlastite
poruke razgovora, drukčije od onih u opisu protokola. Što se od toga
ujednačuje, još nije odlučeno.

## Odakle

Protokol je nastao u programu
[goCOP](https://github.com/tkraljevic/goCOP), gdje i danas radi. syncnet
ga izdvaja u biblioteku koju može koristiti bilo koja aplikacija. Opis i
vektori ovdje pokazuju žicu kakva je danas u tom programu. Izvedba u Rustu
nastala je u programu
[List2Cart](https://github.com/tkraljevic/List2Cart).

## Licenca

MIT. Tekst je u datoteci [LICENSE](LICENSE).

Dijelovi ovog projekta razvijeni su uz pomoć alata umjetne inteligencije.
