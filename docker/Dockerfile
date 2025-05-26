FROM kosztadani/wireshark-plugin-env:0.1

COPY docker/build.sh /src/
COPY CMakeLists.txt /src/plugin/
COPY wireshark-plugin /src/plugin/wireshark-plugin

RUN echo "Building plugin" \
 && /src/build.sh linux 4.4 \
 && /src/build.sh mingw 4.4
