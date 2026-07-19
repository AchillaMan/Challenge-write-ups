FROM debian:buster-slim
COPY ./mipsy /app/mipsy
ENV DEBIAN_FRONTEND="noninteractive"
RUN apt-get update --fix-missing                 && \
    apt-get install -qy --no-install-recommends     \
        libc6-mips64-cross=2.28-7cross2             \
        qemu-user=1:3.1+dfsg-8+deb10u8              \
        socat=1.7.3.2-2                          && \
    apt-get clean                                && \
    rm -rf /var/lib/apt/lists/                   && \
	rm /etc/ld.so.cache                          && \
	chmod +x /app/mipsy

EXPOSE 4000
CMD ["/usr/bin/socat", "tcp-listen:4000,reuseaddr,fork", "exec:'qemu-mips64 -L /usr/mips64-linux-gnuabi64 /app/mipsy'"]
