using System;
using System.IO;
using Novell.Directory.Ldap.Asn1;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// PrincipalName   ::= SEQUENCE {
    ///         name-type       [0] Int32,
    ///         name-string     [1] SEQUENCE OF KerberosString
    /// }
    public class PrincipalName : KerberosAsn1Object
    {
        public NameType Type { get; set; }
        public string[] Name { get; set; }

        public PrincipalName() : base(Asn1Sequence.Id)
        {
        }

        public PrincipalName(Asn1Tagged input, IAsn1Decoder decoder) : base(Asn1Sequence.Id)
        {
            foreach (var item in IterateThroughSequence(input, decoder, contextTagsOnly: true))
            {
                var itemId = item.GetIdentifier();

                var ostring = (Asn1OctetString)item.TaggedValue;
                switch (itemId.Tag)
                {
                    case 0:
                        Type = (NameType)DecodeInteger(ostring, decoder);
                        break;
                    case 1:
                        var names = ostring.DecodeAs<Asn1Sequence>(decoder);
                        Name = IterateAndTransform(names, (ix, asn1) =>
                        {
                            var ns = asn1 as Asn1GeneralString;
                            return ns.StringValue();
                        });
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
