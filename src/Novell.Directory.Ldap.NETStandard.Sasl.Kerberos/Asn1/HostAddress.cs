using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Asn1
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

        public HostAddress(Asn1Tagged input, IAsn1Decoder decoder)
            : base(Asn1Sequence.Id)
        {
            foreach (var item in IterateThroughSequence(input, decoder, contextTagsOnly: true))
            {
                var itemId = item.GetIdentifier();
                var ostring = (Asn1OctetString)item.TaggedValue;
                switch (itemId.Tag)
                {
                    case 1:
                        Type = (AddressType)DecodeInteger(ostring, decoder);
                        break;
                    case 2:
                        Address = ostring.ByteValue();
                        break;
                }
            }
        }

        public override void Encode(IAsn1Encoder enc, Stream outRenamed)
        {
            throw new NotImplementedException();
        }
    }
}
