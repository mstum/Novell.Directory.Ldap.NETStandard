using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// Note: This is supposed to eventually replace <see cref="LberDecoder"/>.
    /// It is meant to offer extensibility (<see cref="KerberosDecoder"/>) that
    /// the LberDecoder doesn't yet, and be more of a "general purpose" ASN.1 deserializer.
    /// 
    /// However, right now it's only used for the Kerberos stuff, hence it lives here until
    /// it's ready to go down into the Core project.
    /// </summary>
    public class BerDecoder : IAsn1Decoder
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
