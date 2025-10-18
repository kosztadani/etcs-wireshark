FROM kosztadani/wireshark-plugin-env:0.2

COPY docker/build.sh /src/
COPY CMakeLists.txt /src/plugin/
COPY wireshark-plugin /src/plugin/wireshark-plugin

RUN echo "Building plugin" \
 && /src/build.sh linux 4.0 \
 && /src/build.sh linux 4.2 \
 && /src/build.sh linux 4.4 \
 && /src/build.sh linux 4.6 \
 && /src/build.sh mingw 4.2 \
 && /src/build.sh mingw 4.4 \
 && /src/build.sh mingw 4.6
