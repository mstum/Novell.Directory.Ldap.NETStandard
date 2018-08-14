using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// PA-DATA         ::= SEQUENCE {
    ///         -- NOTE: first tag is [1], not [0]
    ///         padata-type     [1] Int32,
    ///         padata-value    [2] OCTET STRING -- might be encoded AP-REQ
    /// }
    /// </summary>
    public class PreAuthenticationData : KerberosAsn1Object
    {
        public PaDataType Type { get; set; }
        public byte[] Value { get; set; }

        public PreAuthenticationData()
            : base(Asn1Sequence.Id)
        {
        }

        public PreAuthenticationData(Asn1Object input, IAsn1Decoder decoder)
            : this()
        {
            foreach (var item in IterateThroughSequence(input, decoder, contextTagsOnly: true))
            {
                var itemId = item.GetIdentifier();
                var ostring = (Asn1OctetString)item.TaggedValue;
                switch (itemId.Tag)
                {
                    case 1:
                        Type = (PaDataType)DecodeInteger(ostring, decoder);
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
    }
}
