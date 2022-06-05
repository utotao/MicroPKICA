// MicroPKICA.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "WinSock2.h" // 得放在最上面，不然会报未定义标识符
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <Windows.h>
#include <process.h>
extern "C"
{
#include <openssl/applink.c>
};

using namespace std;

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

// 生成证书系统
int PkicaGenerateCertfile(void)
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

    // 签发subca


    // 签发设备证书


    // 使用设备证书签名

    // 验证签名

    // 验证证书链
    return 0;
}

// 证书文件检查
int PkicaCheckCertFile()
{
    return 0;
}

int PkicaCheckCertState()
{
    if (PkicaCheckCertFile() == 0) {
        PkicaGenerateCertfile();
    } else {
        cout << "prikey match sucess!" << endl;
    }
    return 0;
}

void ClientThreadProc(void* arg)
{
    WORD sockVersion = MAKEWORD(2, 2);
    WSADATA data;
    if (WSAStartup(sockVersion, &data) != 0) {
        return;
    }
    
    SOCKET sclient = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sclient == INVALID_SOCKET) {
        printf("invalid socket!");
        return;
    }

    sockaddr_in serAddr;
    serAddr.sin_family = AF_INET;
    serAddr.sin_port = htons(8888);
    serAddr.sin_addr.S_un.S_addr = inet_addr("192.168.199.194");
    if (connect(sclient, (sockaddr*)&serAddr, sizeof(serAddr)) == SOCKET_ERROR) { //连接失败 
        printf("connect error !");
        closesocket(sclient);
        return;
    }

    const char* sendData = "123456";
    send(sclient, sendData, strlen(sendData), 0);
    //send()用来将数据由指定的socket传给对方主机
    //int send(int s, const void * msg, int len, unsigned int flags)
    //s为已建立好连接的socket，msg指向数据内容，len则为数据长度，参数flags一般设0
    //成功则返回实际传送出去的字符数，失败返回-1，错误原因存于error 

    char recData[255] = {0};
    int ret = recv(sclient, recData, 255, 0);
    if (ret > 0) {
        printf("\r\n Client get recData = %s. \r\n", recData);
    }
    closesocket(sclient);
    WSACleanup();
}

void ServerThreadProc(void* arg)
{
    //初始化WSA  
    WORD sockVersion = MAKEWORD(2, 2);
    WSADATA wsaData;
    if (WSAStartup(sockVersion, &wsaData) != 0) {
        return;
    }

    //创建套接字  
    SOCKET slisten = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (slisten == INVALID_SOCKET) {
        printf("socket error !");
        return;
    }

    //绑定IP和端口  
    sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(8888);
    sin.sin_addr.S_un.S_addr = INADDR_ANY;
    if (bind(slisten, (LPSOCKADDR)&sin, sizeof(sin)) == SOCKET_ERROR) {
        printf("bind error !");
    }

    //开始监听  
    if (listen(slisten, 5) == SOCKET_ERROR) {
        printf("listen error !");
        return;
    }

    //循环接收数据  
    SOCKET sClient;
    sockaddr_in remoteAddr;
    int nAddrlen = sizeof(remoteAddr);
    char revData[255] = {0};
    static unsigned int cnt = 0;
    while (true)
    {
        printf("等待连接... cnt = %u. \n", cnt++);
        sClient = accept(slisten, (SOCKADDR*)&remoteAddr, &nAddrlen);
        if (sClient == INVALID_SOCKET) {
            printf("accept error !");
            continue;
        }
        printf("Server 接受到一个连接：%s \r\n", inet_ntoa(remoteAddr.sin_addr));

        //接收数据
        int ret = recv(sClient, revData, 255, 0);
        if (ret > 0) {
            printf("\r\n Server receive revData = %s. \r\n", revData);
            /*revData[ret] = 0x00;
            printf(revData);*/
        }

        //发送数据  
        const char* sendData = "你好，TCP客户端！\n";
        send(sClient, sendData, strlen(sendData), 0);
        closesocket(sClient);
    }

    closesocket(slisten);
    WSACleanup();
}

int main()
{
    HANDLE h1, h2;
    // 检查证书：rootca.cer->subca.cer->client.cer/server.cer
    PkicaCheckCertState();

    // 启动线程1创建client-socket-client.cer
    h1 = (HANDLE)_beginthread(ClientThreadProc, 0, NULL);
    // 启动线程2创建client-server-server.cer
    h2 = (HANDLE)_beginthread(ServerThreadProc, 0, NULL);

    WaitForSingleObject(h1, INFINITE);//等待线程1结束
    WaitForSingleObject(h2, INFINITE);//等待线程2结束

    return 0;
}
