#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "certificate.h"

/* Serial Number buffer length */
#define SERIAL_NUM_LEN 1024

/* Signature algorithms buffer length */
#define SIG_ALGO_LEN 64

/* Public key algorithms buffer length */
#define PUBKEY_ALGO_LEN 64

#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>

#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/objects.h>


struct CertificateContext
{
  X509 * cert;
};


void init_cert_ctx()
{
  OpenSSL_add_all_algorithms();
}

struct CertificateContext * alloc_cert_cxt(const unsigned char * data, size_t len)
{
  struct CertificateContext * cxt;

  cxt = (struct CertificateContext *) malloc (sizeof (struct CertificateContext) );
  if (cxt == NULL) {
    return NULL;
  }

  cxt->cert = d2i_X509(NULL, &data, len);
  if (cxt->cert == NULL)
    goto err;


  return cxt;

 err:
  if (cxt)
    clean_cert_cxt(cxt);

  return NULL;
}


void clean_cert_cxt(struct CertificateContext * cxt)
{
  if (cxt) {
    if (cxt->cert) {
      X509_free(cxt->cert);
    }
    free(cxt);
  }
}

int get_serial_number_cert_cxt(struct CertificateContext * cxt, char * buf)
{
  X509 * cert = cxt->cert;

  ASN1_INTEGER *serial = X509_get_serialNumber(cert);

  BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
  if (!bn) {
    fprintf(stderr, "unable to convert ASN1INTEGER to BN\n");
    return -1;
  }

  char *tmp = BN_bn2dec(bn);
  if (!tmp) {
    fprintf(stderr, "unable to convert BN to decimal string.\n");
    BN_free(bn);
    return -1;
  }

  if (strlen(tmp) >= SERIAL_NUM_LEN) {
    fprintf(stderr, "buffer length shorter than serial number\n");
    BN_free(bn);
    OPENSSL_free(tmp);
    return -1;
  }

  strncpy(buf, tmp, SERIAL_NUM_LEN);
  BN_free(bn);
  OPENSSL_free(tmp);

  return 0;
}


void get_version_cert_cxt(struct CertificateContext * cxt, int * version)
{
  X509 * cert = cxt->cert;

  *version = (int) X509_get_version(cert) + 1;
}


int get_signature_algo_cxt(struct CertificateContext * cxt, char * buf, int * keylen)
{
  X509 * cert = cxt->cert;

  int sig_algo_nid = OBJ_obj2nid(cert->sig_alg->algorithm);
  int sig_len = cert->signature->length;

  if (sig_algo_nid == NID_undef) {
    fprintf(stderr, "unable to find specified signature algorithm name.\n");
    return -1;
  }

  const char* sig_algo_buf = OBJ_nid2ln(sig_algo_nid);

  if (strlen(sig_algo_buf) > SIG_ALGO_LEN) {
    fprintf(stderr, "signature algorithm name longer than allocated buffer.\n");
    return -1;
  }

  strncpy(buf, sig_algo_buf, SIG_ALGO_LEN);
  *keylen = sig_len; /* signature length unit is *bytes* */

  return 0;
}


/*
static const char * pkey_type_to_string(int type) {
  switch (type) {
  case EVP_PKEY_RSA:
    return "rsa";
  case EVP_PKEY_DSA:
    return "dsa";
  case EVP_PKEY_DH:
    return "dh";
  case EVP_PKEY_EC:
    return "ec";
  default:
    return "unknown";
  }
}
*/


int get_publick_key_cxt(struct CertificateContext * cxt, char * buf, int * kbits) 
{
  X509 * cert = cxt->cert;

  // char pubkey_algoname[PUBKEY_ALGO_LEN];
  // int pubkey_algonid = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);

  EVP_PKEY * pubkey = X509_get_pubkey( (X509*)cert);

  if (NULL == pubkey) {
    fprintf(stderr, "unable to extract public key from certificate");
    EVP_PKEY_free(pubkey);
    return -1;
  }

  int pubkey_algonid =  EVP_PKEY_type(pubkey->type);

  if (pubkey_algonid == NID_undef) {
    fprintf(stderr, "unable to find specified public key algorithm name.\n");
    EVP_PKEY_free(pubkey);
    return -1;
  }

  const char* sslbuf = OBJ_nid2ln(pubkey_algonid);
  assert(strlen(sslbuf) < PUBKEY_ALGO_LEN);
  strncpy(buf, sslbuf, PUBKEY_ALGO_LEN);

  /*
  EVP_PKEY_RSA
  EVP_PKEY_DSA
  EVP_PKEY_DH
  EVP_PKEY_EC
  */
  int bits = EVP_PKEY_bits(pubkey);
  *kbits = bits;

  EVP_PKEY_free(pubkey);
  return 0;
}