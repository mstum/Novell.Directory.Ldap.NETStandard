using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// Checksum        ::= SEQUENCE {
    ///         cksumtype       [0] Int32,
    ///         checksum        [1] OCTET STRING
    /// }
    /// </summary>
    public class Checksum : KerberosAsn1Object
    {
        public int Type { get; set; }
        public byte[] Value { get; set; }

        public Checksum(Asn1Tagged input, IAsn1Decoder decoder)
             : base(Asn1Sequence.Id)
        {
            foreach (var item in IterateThroughSequence(input, decoder, contextTagsOnly: true))
            {
                var itemId = item.GetIdentifier();
                var ostring = (Asn1OctetString)item.TaggedValue;
                switch (itemId.Tag)
                {
                    case 1:
                        var type = ostring.DecodeAs<Asn1Integer>(decoder);
                        Type = type.IntValue();
                        break;
                    case 2:
                        Value = ostring.ByteValue();
                        break;
                }
            }
        }

        public override void Encode(IAsn1Encoder enc, Stream outRenamed)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Not an enum because the Checksum type seems to be very extensible.
        /// </summary>
        /// <remarks>
        /// https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml
        /// </remarks>
        public static class Types
        {
            // RFC 3961
            public const int CRC32_Id = 1; // Deprecated
            public const int CRC32_Size = 4;

            public const int RsaMd4_Id = 2; // Deprecated
            public const int RsaMd4_Size = 16;

            public const int RsaMd4Des_Id = 3; // Deprecated
            public const int RsaMd4Des_Size = 24;

            public const int DesMac_Id = 4; // Deprecated
            public const int DesMac_Size = 16;

            public const int DesMacK_Id = 5; // Deprecated
            public const int DesMacK_Size = 8;

            public const int RsaMd4DesK_Id = 6; // Deprecated
            public const int RsaMd4DesK_Size = 16;

            public const int RsaMd5_Id = 7; // Deprecated
            public const int RsaMd5_Size = 16;

            public const int RsaMd5Des_Id = 8;
            public const int RsaMd5Des_Size = 24;

            public const int RsaMd5Des3_Id = 9;
            public const int RsaMd5Des3_Size = 24;

            public const int Sha1Unkeyed_Id = 10; // Seems like this exists twice, as ID 10 and 14.
            public const int Sha1Unkeyed_Size = 20;

            // 11 is Unassigned

            public const int HmacSha1Des3Kd_Id = 12; // Deprecated
            public const int HmacSha1Des3Kd_Size = 20;

            public const int HmacSha1Des3_Id = 13; // Deprecated
            public const int HmacSha1Des3_Size = 20;

            public const int Sha1Unkeyed2_Id = 14;
            public const int Sha1Unkeyed2_Size = 20;

            // RFC 3962
            public const int HmacSha1_96Aes128_Id = 15;
            public const int HmacSha1_96Aes128_Size = 20;

            public const int HmacSha1_96Aes256_Id = 16;
            public const int HmacSha1_96Aes256_Size = 20;

            // RFC 6803
            public const int CmacCamellia128_Id = 17;
            public const int CmacCamellia128_Size = 16;

            public const int CmacCamellia256_Id = 18;
            public const int CmacCamellia256_Size = 16;

            // RFC 8009
            public const int HmacSha256_128Aes128_Id = 19;
            public const int HmacSha256_128Aes128_Size = 16;

            public const int HmacSha384_192Aes256_Id = 20;
            public const int HmacSha384_192Aes256_Size = 24;

            // RFC 1964
            public const int Gss_Id = 0x8003;
            public const int Gss_Size = 24;
        }
    }
}
