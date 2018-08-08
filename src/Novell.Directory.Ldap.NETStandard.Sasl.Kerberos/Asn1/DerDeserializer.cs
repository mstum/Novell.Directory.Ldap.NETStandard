using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// A Deserializer for ASN.1 objects encoded under
    /// Distinguished Encoding Rules (DER)
    /// </summary>
    /// <remarks>
    /// While Novell uses "Encoder/Decoder", standard .NET
    /// terminology would call these Serializer/Deserializer
    /// because that's what they are.
    /// </remarks>
    public class DerDeserializer : IAsn1Decoder
    {
        public Asn1Object Decode(byte[] valueRenamed)
        {
            throw new NotImplementedException();
        }

        public Asn1Object Decode(Stream inRenamed)
        {
            throw new NotImplementedException();
        }

        public Asn1Object Decode(Stream inRenamed, int[] length)
        {
            throw new NotImplementedException();
        }

        public bool DecodeBoolean(Stream inRenamed, int len)
        {
            throw new NotImplementedException();
        }

        public string DecodeCharacterString(Stream inRenamed, int len)
        {
            throw new NotImplementedException();
        }

        public long DecodeNumeric(Stream inRenamed, int len)
        {
            throw new NotImplementedException();
        }

        public byte[] DecodeOctetString(Stream inRenamed, int len)
        {
            throw new NotImplementedException();
        }
    }
}
