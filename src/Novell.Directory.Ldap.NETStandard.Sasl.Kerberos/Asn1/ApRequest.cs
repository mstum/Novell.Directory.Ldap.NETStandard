using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Kerberos
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

        public ApRequest(Asn1DecoderProperties props)
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
                        //         pvno            [0] INTEGER (5),
                        var asn1Int = DecodeAs<Asn1Integer>(props);
                        ProtocolVersionNumber = asn1Int.IntValue();
                        return asn1Int;
                    case 1:
                        //         msg-type        [1] INTEGER (14),
                        var asn1MType = DecodeAs<Asn1Integer>(props);
                        Type = (MessageType)asn1MType.IntValue();
                        return asn1MType;
                    case 2:
                        //         ap-options      [2] APOptions,
                        var apOptions = props.DecodeAs<Asn1BitString>();
                        Options = apOptions.ToFlagsEnum<ApOptions>();
                        return apOptions;
                    case 3:
                        //         ticket          [3] Ticket,
                        Ticket = new Ticket(props);
                        return Ticket;
                    case 4:
                        //         authenticator   [4] EncryptedData -- Authenticator
                        Authenticator = new EncryptedData(props);
                        return Authenticator;
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
