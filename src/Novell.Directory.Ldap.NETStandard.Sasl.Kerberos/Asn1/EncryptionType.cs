namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// 
    /// </summary>
    /// <remarks>
    /// Taken from NTSecAPI.h
    /// 
    /// These encryption types are supported by the default MS KERBSUPP DLL
    /// as crypto systems.  Values over 127 are local values, and may be changed
    /// without notice.
    /// </remarks>
    public enum EncryptionType
    {
        NULL = 0,
        DES_CBC_CRC = 1,
        DES_CBC_MD4 = 2,
        DES_CBC_MD5 = 3,

        AES128_CTS_HMAC_SHA1_96 = 17,
        AES256_CTS_HMAC_SHA1_96 = 18,

        // Unsupported but defined types
        DES3_CBC_MD5 = 5,
        DES3_CBC_SHA1 = 7,
        DES3_CBC_SHA1_KD = 16,

        // Deprecated
        DSA_SIGN = 8,

        // Pkinit encryption types
        DSA_SHA1_CMS = 9, // also defined as KERB_ETYPE_RSA_PRIV
        RSA_MD5_CMS = 10, // also defined as KERB_ETYPE_RSA_PUB
        RSA_SHA1_CMS = 11, // also defined as KERB_ETYPE_RSA_PUB_MD5
        RC2_CBC_ENV = 12, // also defined as KERB_ETYPE_RSA_PUB_SHA1
        RSA_ENV = 13, // also defined as KERB_ETYPE_PKCS7_PUB
        RSA_ES_OEAP_ENV = 14,
        DES_EDE3_CBC_ENV = 15,

        // In use types
        DES_CBC_MD5_NT = 20,
        RC4_HMAC_NT = 23,
        RC4_HMAC_NT_EXP = 24,

        RC4_MD4 = -128, // FFFFFF80
        RC4_PLAIN2 = -129,
        RC4_LM = -130,
        RC4_SHA = -131,
        DES_PLAIN = -132,
        RC4_HMAC_OLD = -133, // FFFFFF7B
        RC4_PLAIN_OLD = -134,
        RC4_HMAC_OLD_EXP = -135,
        RC4_PLAIN_OLD_EXP = -136,
        RC4_PLAIN = -140,
        RC4_PLAIN_EXP = -141,

        //
        // used internally by userapi.cxx
        //
        AES128_CTS_HMAC_SHA1_96_PLAIN = -148,
        AES256_CTS_HMAC_SHA1_96_PLAIN = -149,

        //
        // Microsoft-specific value for sending the NTOWF back to the client via AS_REP.
        //
        NTLM_HASH = -150
    }
}
