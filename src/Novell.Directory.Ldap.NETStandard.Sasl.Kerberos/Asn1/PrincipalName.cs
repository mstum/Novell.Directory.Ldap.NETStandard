using System;
using System.IO;
using Novell.Directory.Ldap.Asn1;

namespace Novell.Directory.Ldap.Sasl.Kerberos
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

        public PrincipalName(Asn1DecoderProperties props) : this()
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
                        // name-type       [0] Int32,
                        var asn1Int = props.DecodeAs<Asn1Integer>();
                        Type = (NameType)asn1Int.IntValue();
                        return asn1Int;
                    case 1:
                        // name-string     [1] SEQUENCE OF KerberosString
                        var nameSeq = props.DecodeAs<Asn1Sequence>();
                        Name = nameSeq.Transform<Asn1GeneralString, string>(gs => gs.StringValue());
                        return nameSeq;
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
