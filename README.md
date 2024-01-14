# Pcap Analyzer

## Description
This is a small C program that takes a pcap file as input and displays, at 10-second intervals, a list of IP addresses appearing in the pcap packets along with the number of times they appear. The output is sorted by the frequency of appearances.

## Usage
```bash
./pcap_analyzer example.pcap

1702398733
----------------
1.2.3.4 : 13
4.5.6.7 : 9
3.3.3.3 : 2

1702398743
----------------
1.2.3.4 : 9
1.2.6.7 : 1
...
```


## How to Compile
To compile the program, use a C compiler. For example:
```bash
gcc pcap_analyzer.c -o pcap_analyzer -lpcap
```

## Dependencies

PCAP library : if not already installed, install it using your system's package manager.

Example on debian:

```bash
sudo apt-get install libpcap-dev
```

## TODO

* Utiliser un dictionnaire avec allocation de mémoire dynamique plutôt qu'un tableau statique
* Ajouter TU
* Mettre les fonctions relatives au fichier PCAP et relatives au tri dans des fichiers .c et .h séparés (et ajouter static au fonction locales)
* Prendre time de wireshark plutot que le timestamp epoch précis à la seconde près seulement

## License

This program is released under the MIT License.