using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Kerberos
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

        public PreAuthenticationData(Asn1DecoderProperties props)
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
                        // padata-type     [1] Int32,
                        var asn1Int = DecodeAs<Asn1Integer>(props);
                        Type = (PaDataType)asn1Int.IntValue();
                        return asn1Int;
                    case 2:
                        // padata-value    [2] OCTET STRING -- might be encoded AP-REQ
                        var paDataValue = DecodeAs<Asn1OctetString>(props);
                        Value = paDataValue.ByteValue();
                        return paDataValue;
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
