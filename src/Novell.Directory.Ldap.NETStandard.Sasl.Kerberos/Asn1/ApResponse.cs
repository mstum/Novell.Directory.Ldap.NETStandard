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

        public ApResponse(Asn1Tagged input, IAsn1Decoder decoder)
            : base(Id)
        {
            foreach (var item in IterateThroughSequence(input, decoder, contextTagsOnly: true))
            {
                var itemId = item.GetIdentifier();
                var ostring = (Asn1OctetString)item.TaggedValue;
                switch (itemId.Tag)
                {
                    case 0:
                        ProtocolVersionNumber = (int)DecodeInteger(ostring, decoder);
                        break;
                    case 1:
                        Type = (MessageType)DecodeInteger(ostring, decoder);
                        break;
                    case 2:
                        EncPart = new EncryptedData(item, decoder);
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
