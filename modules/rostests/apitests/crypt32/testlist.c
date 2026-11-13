
#define STANDALONE
#include <apitest.h>

extern void func_CertChainEngine(void);
extern void func_CertEnumSystemStore(void);
extern void func_CertEnumSystemStoreLocation(void);
extern void func_ChainTrust(void);
extern void func_RootStoreSeed(void);
extern void func_CryptExportPublicKeyInfoFromBCryptKeyHandle(void);
extern void func_CryptTimeStamp(void);
extern void func_CryptStringToBinaryStrict(void);

const struct test winetest_testlist[] =
{
    { "CertChainEngine", func_CertChainEngine },
    { "CertEnumSystemStore", func_CertEnumSystemStore },
    { "CertEnumSystemStoreLocation", func_CertEnumSystemStoreLocation },
    { "ChainTrust", func_ChainTrust },
    { "RootStoreSeed", func_RootStoreSeed },
    { "CryptExportPublicKeyInfoFromBCryptKeyHandle", func_CryptExportPublicKeyInfoFromBCryptKeyHandle },
    { "CryptTimeStamp", func_CryptTimeStamp },
    { "CryptStringToBinaryStrict", func_CryptStringToBinaryStrict },

    { 0, 0 }
};
