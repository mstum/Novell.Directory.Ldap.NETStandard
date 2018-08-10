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
        public int Type { get; set; }
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
                        var type = ostring.DecodeAs<Asn1Integer>(decoder);
                        Type = type.IntValue();
                        break;
                    case 1:
                        var names = ostring.DecodeAs<Asn1Sequence>(decoder);
                        var size = names.Size();
                        var nr = new string[size];

                        for (int i = 0; i < size; i++)
                        {
                            var nameItem = names.get_Renamed(i) as Asn1GeneralString;
                            nr[i] = nameItem.StringValue();
                        }
                        Name = nr;
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
