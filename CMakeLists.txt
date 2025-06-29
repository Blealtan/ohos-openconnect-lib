cmake_minimum_required(VERSION 3.16)

project(openconnect LANGUAGES C)

set(SOURCES
    version.c
    ssl.c
    http.c
    textbuf.c
    http-auth.c
    auth-common.c
    auth-html.c
    library.c
    compat.c
    lzs.c
    mainloop.c
    script.c
    ntlm.c
    digest.c
    mtucalc.c
    oncp.c
    lzo.c
    auth-juniper.c
    esp.c
    esp-seqno.c
    openssl-esp.c
    auth.c
    cstp.c
    hpke.c
    multicert.c
    dtls.c
    openssl-dtls.c
    oath.c
    gpst.c
    auth-globalprotect.c
    pulse.c
    oidc.c
    ppp.c
    nullppp.c
    f5.c
    fortinet.c
    jsondump.c
    array.c
    vhost.c
    openssl.c
    openssl-pkcs11.c
    iconv.c
    json/json.c
    tun.c
)

add_library(openconnect SHARED ${SOURCES})
target_compile_definitions(openconnect PRIVATE LIBOPENCONNECT_EXPORTS)

target_include_directories(openconnect PRIVATE
    ${PROJECT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/json
)

target_link_libraries(openconnect PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    LibXml2
    z m
)
