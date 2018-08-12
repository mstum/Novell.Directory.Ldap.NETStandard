using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// -- NOTE: AuthorizationData is always used as an OPTIONAL field and
    /// -- should not be empty.
    /// AuthorizationData       ::= SEQUENCE OF SEQUENCE {
    ///         ad-type         [0] Int32,
    ///         ad-data         [1] OCTET STRING
    /// }
    /// </summary>
    public class AuthorizationData : KerberosAsn1Object
    {
        public int Type { get; set; }
        public byte[] Data { get; set; }

        public AuthorizationData()
            : base(Asn1Sequence.Id)
        {
        }

        public AuthorizationData(Asn1Tagged input, IAsn1Decoder decoder)
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
                        Data = ostring.ByteValue();
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
