#ifndef __CERTIFICATE_H__
#define __CERTIFICATE_H__

struct CertificateContext;

void init_cert_ctx();

struct CertificateContext * alloc_cert_cxt(const unsigned char * data, size_t len);

void clean_cert_cxt(struct CertificateContext * cxt);

int get_serial_number_cert_cxt(struct CertificateContext * cxt, char * buf);

void get_version_cert_cxt(struct CertificateContext * cxt, int * version);

int get_signature_algo_cxt(struct CertificateContext * cxt, char * buf, int * keylen);

int get_publick_key_cxt(struct CertificateContext * cxt, char * buf, int * kbits);

#endif /* __CERTIFICATE_H__ */
