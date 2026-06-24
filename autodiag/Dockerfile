FROM debian:trixie-slim
WORKDIR /
COPY ./fs/ /
COPY --chown=root:root --chmod=400 ./src/flag.txt /
RUN apt-get update                                                  && \
    apt-get install -y --no-install-recommends                         \
        libdbus-1-3=1.*                                                \
        libssl3t64=3.*                                                 \
        zlib1g=1:1.*                                                   \
        dbus=1.*                                                       \
        socat=1.*                                                   && \
    rm -rf /var/lib/apt/lists/*                                     && \
                                                                       \
    groupadd -r -g 999 ivi                                          && \
    useradd -r -u 999 -g 999 -M                                        \
        -s /usr/sbin/nologin ivi                                    && \
    dbus-uuidgen --ensure=/etc/machine-id                           && \
                                                                       \
    mkdir -p                                                           \
        /etc/ivi                                                       \
        /var/lib/ivi/assets                                            \
        /usr/share/dbus-1/services                                  && \
    chown -R root:root                                                 \
        /opt/ivi                                                       \
        /var/lib/ivi                                                   \
        /usr/local/bin/ivi_server                                      \
        /usr/local/sbin/ivi_dbusd                                      \
        /usr/local/sbin/ivi_dbusd_wrapper                              \
        /printflag                                                  && \
    chown nobody:nogroup                                               \
        /opt/ivi/bin/ivi_update_runner                                 \
        /opt/ivi/bin/ivi_diag_runner                                && \
    chmod 0755                                                         \
        /usr/local/bin/run.sh                                          \
        /usr/local/bin/ivi_server                                      \
        /usr/local/sbin/ivi_dbusd                                      \
        /usr/local/sbin/ivi_dbusd_wrapper                              \
        /opt/ivi/bin/ivi_diag_runner                                   \
        /opt/ivi/bin/ivi_update_runner                                 \
        /opt/ivi/lib                                                && \
    chmod 0644                                                         \
        /usr/share/dbus-1/services/com.acme.ivi.ServiceManager.service \
        /etc/ivi/update_public.pem                                     \
        /opt/ivi/lib/libivi_diag.so                                 && \
    chmod 6755                                                         \
        /opt/ivi/bin/ivi_diag_runner                                   \
        /opt/ivi/bin/ivi_update_runner                              && \
    chmod 4755 /printflag
EXPOSE 4000
USER ivi
CMD ["/usr/local/bin/run.sh"]
