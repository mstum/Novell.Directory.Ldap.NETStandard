using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Kerberos
{
    /// <summary>
    /// AP-REP          ::= [APPLICATION 15] SEQUENCE {
    ///         pvno            [0] INTEGER (5),
    ///         msg-type        [1] INTEGER (15),
    ///         enc-part        [2] EncryptedData -- EncAPRepPart
    /// }
    /// </summary>
    public class ApResponse : KerberosAsn1Object
    {
        public static readonly Asn1Identifier Id = new Asn1Identifier(TagClass.Application, true, 15);

        public int ProtocolVersionNumber { get; set; }
        public MessageType Type { get; set; }
        public EncryptedData EncPart { get; set; }

        public ApResponse()
            : base(Id)
        {
        }

        public ApResponse(Asn1DecoderProperties props)
            : base(Id)
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
                        //         pvno            [0] INTEGER (5)
                        var asn1Int = DecodeAs<Asn1Integer>(props);
                        ProtocolVersionNumber = asn1Int.IntValue();
                        return asn1Int;
                    case 1:
                        //         msg-type        [1] INTEGER (15),
                        var asn1MType = DecodeAs<Asn1Integer>(props);
                        Type = (MessageType)asn1MType.IntValue();
                        return asn1MType;
                    case 2:
                        //         enc-part        [2] EncryptedData -- EncAPRepPart
                        EncPart = new EncryptedData(props);
                        return EncPart;
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
