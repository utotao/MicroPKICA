// MicroPKICA.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
extern "C"
{
#include <openssl/applink.c>
};

void PkicaSslLibrariInit()
{
    SSL_library_init();
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
}

/*************************************************
 * 函数功能：生产公私钥
 *************************************************/
int PkicaCreateKeyPair(EVP_PKEY** keyPair, int algType)
{
    EVP_PKEY_CTX* ctx = nullptr;
    EVP_PKEY* keyPairTmp = nullptr;

    ctx = EVP_PKEY_CTX_new_id(algType, nullptr);

    EVP_PKEY_keygen_init(ctx);

    EVP_PKEY_keygen(ctx, &keyPairTmp);

    *keyPair = keyPairTmp;
    return 0;
}

int PkicaAddExt(X509* issuer, X509* subject, int nid, char* value, unsigned int valueLen)
{
    X509_EXTENSION* ex = nullptr;
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, subject, nullptr, nullptr, 0);
    ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);

    X509_add_ext(subject, ex, -1);

    X509_EXTENSION_free(ex);
    return 0;
}

int CertMakeRandSerial(ASN1_INTEGER* serial)
{
    BIGNUM* bignum = BN_new();
    BN_pseudo_rand(bignum, 64, 0, 0);
    BN_to_ASN1_INTEGER(bignum, serial);
    return 0;
}

int PkicaSignX509Cert(EVP_PKEY* keyPair, X509** rootca)
{
    ASN1_INTEGER* serialNum = nullptr;
    X509* rootCert = nullptr;
    X509_NAME* rootcaSubName = nullptr;
    const char* keyUsage = "critical,keyCertSign,cRLSign";
    const char* basicConstraints = "critical,CA:true";
    const char* subjectKeyIdentifier = "hash";
    const char* countryName = "CN";
    const char* organizationName = "CISSP";
    const char* organizationUnitName = "security";
    const char* commonName = "pkica";

    rootCert = X509_new();
    serialNum = ASN1_INTEGER_new();
    // 生产随机数
    CertMakeRandSerial(serialNum);
    X509_set_serialNumber(rootCert, serialNum);
    // 设置有效期
    X509_gmtime_adj(X509_get_notBefore(rootCert), 0);
    X509_gmtime_adj(X509_get_notAfter(rootCert), 3600 * 24 * 365);
    // version
    X509_set_version(rootCert, 2);
    // 设置公私钥
    X509_set_pubkey(rootCert, keyPair);
    // 设置subject
    rootcaSubName = X509_get_subject_name(rootCert);
    X509_NAME_add_entry_by_txt(rootcaSubName, "countryName", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(countryName), -1, -1, 0);
    X509_NAME_add_entry_by_txt(rootcaSubName, "organizationName", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(organizationName), -1, -1, 0);
    X509_NAME_add_entry_by_txt(rootcaSubName, "organizationUnitName", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(organizationUnitName), -1, -1, 0);
    X509_NAME_add_entry_by_txt(rootcaSubName, "commonName", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(commonName), -1, -1, 0);
    // 设置keyusage
    PkicaAddExt(rootCert, rootCert, NID_key_usage, const_cast<char*>(keyUsage), strlen(keyUsage));
    PkicaAddExt(rootCert, rootCert, NID_subject_key_identifier, const_cast<char*>(subjectKeyIdentifier), strlen(subjectKeyIdentifier));
    PkicaAddExt(rootCert, rootCert, NID_basic_constraints, const_cast<char*>(basicConstraints), strlen(basicConstraints));
    // 设置自签发
    X509_set_issuer_name(rootCert, rootcaSubName);
    X509_sign(rootCert, keyPair, nullptr);
    *rootca = rootCert;
    return 0;
}

#define EXAMPLE_MACRO_NAME
int main()
{
    EVP_PKEY* keyPair = nullptr;
    X509* rootca = nullptr;
    FILE* keyFile = nullptr;
    FILE* certFile = nullptr;
    // pkica初始化
    PkicaSslLibrariInit();
    PkicaCreateKeyPair(&keyPair, 1087);
    // 签发证书
    PkicaSignX509Cert(keyPair, &rootca);

    // 保存证书
    fopen_s(&keyFile, "./rootcert.key", "w");
    if (keyFile != nullptr) {
        PEM_write_PrivateKey(keyFile, keyPair, nullptr, nullptr, 0, nullptr, nullptr);
    }
    
    fopen_s(&certFile, "./rootcert.cer", "w");
    if (certFile != nullptr) {
        PEM_write_X509(certFile, rootca);
    }
    return 0;
}
