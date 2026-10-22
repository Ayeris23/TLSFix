#include "tlsfix.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <sys/stat.h>
#include <pthread.h>
#include <string.h>

// ECC fallback, iOS 3 and 4 Security framework cannot verify EC keys or ECDSA signatures.

#define PROFILES_DIR "/var/mobile/Library/ConfigurationProfiles"

int tlsfix_ecc_fallback = 0;
OSStatus (*o_TrustEvaluate)(SecTrustRef, SecTrustResultType *) = SecTrustEvaluate;

static int is_ec(X509 *x) {
    EVP_PKEY *k = X509_get0_pubkey(x);

    if (k && EVP_PKEY_base_id(k) == EVP_PKEY_EC) return 1;

    int pk = 0;
    return OBJ_find_sigid_algs(X509_get_signature_nid(x), NULL, &pk) && pk == EVP_PKEY_EC;
}

int ecc_in_chain(STACK_OF(X509) *chain) {
    for (int i = 0; chain && i < sk_X509_num(chain); i++) {
        if (is_ec(sk_X509_value(chain, i))) return 1;
    }

    return 0;
}

// the profiles CA certificates, reloaded whenever a profile is added or removed
static pthread_mutex_t gAnchorLock = PTHREAD_MUTEX_INITIALIZER;
static X509_STORE *gAnchors = NULL;
static time_t gAnchorsStamp = -1;

static void add_payload_cert(X509_STORE *store, CFDictionaryRef payload) {
    CFStringRef type = CFDictionaryGetValue(payload, CFSTR("PayloadType"));
    CFDataRef der = CFDictionaryGetValue(payload, CFSTR("PayloadContent"));

    if (!type || CFGetTypeID(type) != CFStringGetTypeID()) return;
    if (!der || CFGetTypeID(der) != CFDataGetTypeID()) return;

    int root = CFEqual(type, CFSTR("com.apple.security.root"));
    int cert = CFEqual(type, CFSTR("com.apple.security.pkcs1"));

    if (!root && !cert) return;

    const unsigned char *p = CFDataGetBytePtr(der);
    X509 *x = d2i_X509(NULL, &p, CFDataGetLength(der));

    if (!x) return;

    if (X509_check_ca(x) > 0 && X509_check_issued(x, x) == X509_V_OK) {
        X509_STORE_add_cert(store, x);
    }

    X509_free(x);
}

static void add_profile(X509_STORE *store, const char *path) {
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, strlen(path), false);
    CFDataRef data = NULL;

    if (url) {
        CFURLCreateDataAndPropertiesFromResource(NULL, url, &data, NULL, NULL, NULL);
        CFRelease(url);
    }

    if (!data) return;

    CFPropertyListRef plist = CFPropertyListCreateFromXMLData(NULL, data, kCFPropertyListImmutable, NULL);
    CFRelease(data);

    if (!plist) return;

    CFArrayRef payloads = NULL;

    if (CFGetTypeID(plist) == CFDictionaryGetTypeID()) {
        payloads = CFDictionaryGetValue(plist, CFSTR("PayloadContent"));
    }

    if (payloads && CFGetTypeID(payloads) == CFArrayGetTypeID()) {
        for (CFIndex i = 0; i < CFArrayGetCount(payloads); i++) {
            CFDictionaryRef payload = CFArrayGetValueAtIndex(payloads, i);

            if (payload && CFGetTypeID(payload) == CFDictionaryGetTypeID()) {
                add_payload_cert(store, payload);
            }
        }
    }

    CFRelease(plist);
}

static X509_STORE *copy_anchors(void) {
    struct stat st;
    time_t stamp = stat(PROFILES_DIR, &st) == 0 ? st.st_mtime : 0;

    pthread_mutex_lock(&gAnchorLock);

    if (stamp != gAnchorsStamp) {
        X509_STORE *store = X509_STORE_new();
        DIR *dir = store ? opendir(PROFILES_DIR) : NULL;
        struct dirent *e;
        char path[1024];

        while (dir && (e = readdir(dir))) {
            size_t n = strlen(e->d_name);
            int stub = n > 5 && !strcmp(e->d_name + n - 5, ".stub");

            if (e->d_name[0] == '.' || stub) continue;

            if (snprintf(path, sizeof path, "%s/%s", PROFILES_DIR, e->d_name) < (int)sizeof path) {
                add_profile(store, path);
            }
        }

        if (dir) closedir(dir);
        if (gAnchors) X509_STORE_free(gAnchors);

        gAnchors = store;
        gAnchorsStamp = stamp;
    }

    X509_STORE *store = gAnchors;

    if (store) X509_STORE_up_ref(store);

    pthread_mutex_unlock(&gAnchorLock);
    return store;
}

// the same checks as the system's SSL policy: signatures and dates up to an anchor, a server certificate, and the host's name
int ecc_verify(STACK_OF(X509) *chain, const char *host) {
    if (!chain || sk_X509_num(chain) < 1) return 0;

    X509_STORE *anchors = copy_anchors();

    if (!anchors) return 0;

    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    int ok = 0;

    if (ctx && X509_STORE_CTX_init(ctx, anchors, sk_X509_value(chain, 0), chain)) {
        X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SSL_SERVER);
        X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);
        unsigned char ip[16];

        if (host && host[0]) {
            int literal = inet_pton(AF_INET, host, ip) == 1 || inet_pton(AF_INET6, host, ip) == 1;

            if (literal) X509_VERIFY_PARAM_set1_ip_asc(param, host);
            else X509_VERIFY_PARAM_set1_host(param, host, 0);
        }

        ok = X509_verify_cert(ctx) == 1;
    }

    if (ctx) X509_STORE_CTX_free(ctx);

    X509_STORE_free(anchors);
    return ok;
}
