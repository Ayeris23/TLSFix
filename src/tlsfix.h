#ifndef TLSFIX_H
#define TLSFIX_H

#include <Security/SecureTransport.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <openssl/ssl.h>

// Secure Transport result codes
#ifndef errSSLWouldBlock
#define errSSLWouldBlock  -9803
#endif

#define ST_ClosedGraceful -9805
#define ST_ClosedAbort    -9806
#define ST_PeerAuth       -9841
#define ST_Connected       2
#define ST_TLS12           8

typedef struct {
    SSLContextRef    ctx;
    SSLReadFunc      rf;
    SSLWriteFunc     wf;
    SSLConnectionRef conn;
    char             host[256];
    int              inited;
    int              state;
    int              breakAuth;
    int              approved;
    int              clientBypass;
    X509            *clientX509;
    STACK_OF(X509)  *clientChain;
    SecKeyRef        clientKey;
    unsigned         lastUse;
    int              refcount;
    SSL             *ssl;
    SecTrustRef      eccTrust;
} Shadow;

int ensure_ready(void);
Shadow *sh_get(SSLContextRef c);
Shadow *sh_create(SSLContextRef c);
void sh_release(Shadow *s);
void sh_free(SSLContextRef c);
int ossl_init(Shadow *s);
void capture_identity(Shadow *s, CFArrayRef certRefs);
int sh_build_trust(Shadow *s, SecTrustRef *trust);
CFArrayRef sh_cert_array(Shadow *s);
int sh_trust_verified(SecTrustRef t);
void sh_forget_trust(SecTrustRef t);

extern int tlsfix_ecc_fallback;
extern OSStatus (*o_TrustEvaluate)(SecTrustRef, SecTrustResultType *);
int ecc_in_chain(STACK_OF(X509) *chain);
int ecc_verify(STACK_OF(X509) *chain, const char *host);

#endif
