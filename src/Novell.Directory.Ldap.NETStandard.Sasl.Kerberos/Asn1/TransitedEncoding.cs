using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Kerberos
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

        public TransitedEncoding(Asn1DecoderProperties props)
            : base(Asn1Sequence.Id)
        {
            foreach (var item in IterateThroughSequence(input, decoder, contextTagsOnly: true))
            {
                var itemId = item.GetIdentifier();
                var ostring = (Asn1OctetString)item.TaggedValue;
                switch (itemId.Tag)
                {
                    case 1:
                        Type = (int)DecodeInteger(ostring, decoder);
                        break;
                    case 2:
                        Contents = ostring.ByteValue();
                        break;
                }
            }
        }

        private Asn1Object DecodeContentTagHandler(Asn1DecoderProperties props)
        {
            var id = props.Identifier;
            var dec = props.Decoder;
            if (id.IsContext)
            {
                switch (id.Tag)
                {
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
