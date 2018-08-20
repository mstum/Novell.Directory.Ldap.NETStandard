using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Kerberos
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

        public AuthorizationData(Asn1DecoderProperties props)
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
                        //         ad-type         [0] Int32,
                        var asn1Int = DecodeAs<Asn1Integer>(props);
                        Type = asn1Int.IntValue();
                        return asn1Int;
                    case 1:
                        //         ad-data         [1] OCTET STRING
                        var adata = DecodeAs<Asn1OctetString>(props);
                        Data = adata.ByteValue();
                        return adata;
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
