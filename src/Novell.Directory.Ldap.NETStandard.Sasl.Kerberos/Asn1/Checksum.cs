using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Kerberos
{
    /// <summary>
    /// Checksum        ::= SEQUENCE {
    ///         cksumtype       [0] Int32,
    ///         checksum        [1] OCTET STRING
    /// }
    /// </summary>
    public class Checksum : KerberosAsn1Object
    {
        public ChecksumType Type { get; set; }
        public byte[] Value { get; set; }

        public Checksum(Asn1DecoderProperties props)
             : base(Asn1Sequence.Id)
        {
            props.Decode(DecodeContentTagHandler);
        }

        private Asn1Object DecodeContentTagHandler(Asn1DecoderProperties props)
        {
            var id = props.Identifier;
            var dec = props.Decoder;
            if (id.IsContext)
            {
                switch (id.Tag)
                {
                    case 0:
                        var asn1tvno = DecodeAs<Asn1Integer>(props);
                        Type = (ChecksumType)asn1tvno.IntValue();
                        return asn1tvno;
                    case 1:
                        var value = DecodeAs<Asn1OctetString>(props);
                        Value = value.ByteValue();
                        return value;
                }
            }
            return null;
        }

        public override void Encode(IAsn1Encoder enc, Stream outRenamed)
        {
            throw new NotImplementedException();
        }
    }
}
