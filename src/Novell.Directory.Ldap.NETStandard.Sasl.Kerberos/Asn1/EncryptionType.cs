namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <remarks>
    /// These are signed values ranging from -2147483648 to 2147483647.  Positive
    /// values should be assigned only for algorithms specified in accordance
    /// with this specification for use with Kerberos or related protocols.
    /// Negative values are for private use; local and experimental algorithms
    /// should use these values.  Zero is reserved and may not be assigned.
    /// </remarks>
    public enum EncryptionType : int
    {
        // 0: reserved

        DES_CBC_CRC = 1, // Deprecated

        DES_CBC_MD4 = 2, // Deprecated

        DES_CBC_MD5 = 3, // Deprecated

        // 4: Reserved

        DES3_CBC_MD5 = 5, // Deprecated

        // 6: Reserved

        DES3_CBC_SHA1 = 7, // Deprecated
        
        // 8: Unassigned

        DSA_SHA1_CMS = 9,

        RSA_MD5_CMS = 10,

        RSA_SHA1_CMS = 11,

        RC2_CBC_ENV = 12,

        RSA_ENV = 13,

        RSA_ES_OEAP_ENV = 14,

        DES_EDE3_CBC_ENV = 15,

        DES3_CBC_SHA1_KD = 16, // Deprecated

        AES128_CTS_HMAC_SHA1_96 = 17,

        AES256_CTS_HMAC_SHA1_96 = 18,

        AES128_CTS_HMAC_SHA256_128 = 19,

        AES256_CTS_HMAC_SHA384_192 = 20,

        // 21-22: Unassigned

        RC4_HMAC_NT = 23, // Deprecated

        RC4_HMAC_NT_EXP = 24, // Deprecated

        Camellia128_CTS_CMAC = 25,

        Camellia256_CTS_CMAC = 26,

        // 27-64: Unassigned

        SubkeyKeymaterial = 65,

        // 66-2147483647: Unassigned

        // Taken from NTSecAPI.h
        // TODO: Remove them?
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
