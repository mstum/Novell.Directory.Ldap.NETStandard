using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// AP-REQ          ::= [APPLICATION 14] SEQUENCE {
    ///         pvno            [0] INTEGER (5),
    ///         msg-type        [1] INTEGER (14),
    ///         ap-options      [2] APOptions,
    ///         ticket          [3] Ticket,
    ///         authenticator   [4] EncryptedData -- Authenticator
    /// }
    /// </summary>
    public class ApRequest : KerberosAsn1Object
    {
        public int ProtocolVersionNumber { get; set; }
        public MessageType Type { get; set; }
        public ApOptions Options { get; set; }
        public Ticket Ticket { get; set; }
        public EncryptedData Authenticator { get; set; }

        // TODO: EncryptedData => Authenticator decryption?

        public ApRequest()
            : base(Asn1Sequence.Id)
        {
        }

        public ApRequest(Asn1Tagged input, IAsn1Decoder decoder)
            : base(Asn1Sequence.Id)
        {
            foreach (var item in IterateThroughSequence(input, decoder, contextTagsOnly: true))
            {
                var itemId = item.GetIdentifier();
                var ostring = (Asn1OctetString)item.TaggedValue;
                switch (itemId.Tag)
                {
                    case 1:
                        ProtocolVersionNumber = (int)DecodeInteger(ostring, decoder);
                        break;
                    case 2:
                        Type = (MessageType)DecodeInteger(ostring, decoder);
                        break;
                    case 3:
                        var apOpt = ostring.DecodeAs<Asn1BitString>(decoder);
                        Options = apOpt.ToFlagsEnum<ApOptions>();
                        break;
                    case 4:
                        Ticket = new Ticket(item, decoder);
                        break;
                    case 5:
                        Authenticator = new EncryptedData(item, decoder);
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
