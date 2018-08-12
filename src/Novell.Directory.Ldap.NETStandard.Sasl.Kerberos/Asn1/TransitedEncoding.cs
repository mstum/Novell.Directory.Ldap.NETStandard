using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// -- encoded Transited field
    /// TransitedEncoding       ::= SEQUENCE {
    ///         tr-type         [0] Int32 -- must be registered --,
    ///         contents        [1] OCTET STRING
    /// }
    /// </summary>
    public class TransitedEncoding : KerberosAsn1Object
    {
        public int Type { get; set; }
        public byte[] Contents { get; set; }

        public TransitedEncoding()
            : base(Asn1Sequence.Id)
        {
        }

        public TransitedEncoding(Asn1Tagged input, IAsn1Decoder decoder)
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
                        Contents = ostring.ByteValue();
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
