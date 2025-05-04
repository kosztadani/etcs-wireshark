# ETCS Wireshark

Tooling to dissect [ETCS (European Train Control System)][ETCS B4 R1]
messages with Wireshark.

## Java application (MDB to PCAPNG)

Supported Java version: 21.

To build:

```bash
./gradlew :mdb-to-pcapng:installDist
```

## License

The Java application is released into the public domain.
See [LICENSE.CC0-1.0](LICENSE.CC0-1.0).

## Repository maintenance

### Upgrade dependency locks

To upgrade locked dependencies:

```bash
./gradlew resolveAndLockAll --write-locks
```

## References

[ETCS B4 R1][ETCS B4 R1]

[ETCS B4 R1]: https://www.era.europa.eu/era-folder/1-ccs-tsi-appendix-mandatory-specifications-etcs-b4-r1-rmr-gsm-r-b1-mr1-frmcs-b0-ato-b1
