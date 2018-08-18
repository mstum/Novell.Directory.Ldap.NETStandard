using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Kerberos
{
    /// <summary>
    /// HostAddress     ::= SEQUENCE  {
    ///         addr-type       [0] Int32,
    ///         address         [1] OCTET STRING
    /// }
    /// </summary>
    public class HostAddress : KerberosAsn1Object
    {
        public AddressType Type { get; set; }
        public byte[] Address { get; set; }

        public HostAddress()
            : base(Asn1Sequence.Id)
        {
        }

        public HostAddress(Asn1DecoderProperties props)
            : this()
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
                    case 1:
                        var asn1AType = DecodeAs<Asn1Integer>(props);
                        Type = (AddressType)asn1AType.IntValue();
                        return asn1AType;
                    case 2:
                        var addr = DecodeAs<Asn1OctetString>(props);
                        Address = addr.ByteValue();
                        return addr;
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
