# ETCS Wireshark

Tooling to dissect [ETCS (European Train Control System)][ETCS B4 R1]
messages with Wireshark.

## Java application (MDB to PCAPNG)

This is an application to convert MDB files from [ETCS B4 R1][ETCS B4 R1]
SUBSET-076-6-3 into fake PCAPNG files for testing.

Supported Java version: 21.

To build:

```bash
./gradlew :mdb-to-pcapng:installDist
```

To use:

```bash
mdb-to-pcapng/build/install/mdb-to-pcapng/bin/mdb-to-pcapng \
    /path/to/mdb/file/or/directory
```

You may want to use `mergecap` (usually shipped with Wireshark) to merge the
PCAPNG files into one:

```bash
mergecap -a /path/to/*.pcapng -w all.pcapng
```

## Wireshark plugin

Supported Wireshark version: 4.4.

### Building the plugin

To build the plugin, assuming that you have installed the Wireshark headers
and all necessary dependencies:

```bash
./build.sh
```

If you have Docker, you can use a plugin builder image that I have put together.
This builds the plugin both for Linux and for Windows:

```bash
./build-in-docker.sh
```

The built files are installed into `wireshark-config/my-plugins`.

### Using the plugin

You can use the included starter script which will load the plugin and a
Wireshark profile:

```bash
./wireshark.sh
```

## License

The Java application is released into the public domain.
See [LICENSE.CC0-1.0](LICENSE.CC0-1.0).

Wireshark is licensed under GPLv2 and plugins are considered to be derivative works.
Therefore, GPLv2 also applies to the source code of this plugin.
See [LICENSE.GPL-2.0-only](LICENSE.GPL-2.0-only).

## Repository maintenance

### Upgrade dependency locks

To upgrade locked dependencies:

```bash
./gradlew resolveAndLockAll --write-locks
```

## References

[ETCS B4 R1][ETCS B4 R1]

[ETCS B4 R1]: https://www.era.europa.eu/era-folder/1-ccs-tsi-appendix-mandatory-specifications-etcs-b4-r1-rmr-gsm-r-b1-mr1-frmcs-b0-ato-b1
