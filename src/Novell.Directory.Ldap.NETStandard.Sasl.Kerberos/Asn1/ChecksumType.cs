using System;
using System.Collections.Generic;
using System.Text;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <remarks>
    /// These are signed values ranging from -2147483648 to 2147483647.  Positive
    /// values should be assigned only for algorithms specified in accordance
    /// with this specification for use with Kerberos or related protocols.
    /// Negative values are for private use; local and experimental algorithms
    /// should use these values.  Zero is reserved and may not be assigned.
    /// </remarks>
    public enum ChecksumType
    {
        // 0: Reserved

        CRC32 = 1,

        RsaMd4 = 2,

        RsaMd4Des = 3,

        DesMac = 4,

        DesMacK = 5,

        RsaMd4DesK = 6,

        RsaMd5 = 7,

        RsaMd5Des = 8,

        RsaMd5Des3 = 9,

        Sha1Unkeyed = 10,

        // 11: Unassigned

        HmacSha1Des3Kd = 12,

        HmacSha1Des3 = 13,

        Sha1Unkeyed2 = 14,

        HmacSha1_96_Aes128 = 15,
        HmacSha1_96_Aes256 = 16,

        CmacCamellia128 = 17,

        CmacCamellia256 = 18,

        HmacSha256_128_Aes128 = 19,

        HmacSha384_192_Aes256 = 20,

        // 21-32770: Unassigned

        GssApi = 32771 // 0x8003, RFC 1964

        // 32772-2147483647: Unassigned
    }
}