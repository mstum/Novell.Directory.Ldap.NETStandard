using Novell.Directory.Ldap.Asn1;
using System;
using System.Collections.Generic;

namespace Novell.Directory.Ldap.Sasl.Kerberos
{
    /// <summary>
    /// KDC-REQ         ::= SEQUENCE {
    ///         -- NOTE: first tag is [1], not [0]
    ///         pvno            [1] INTEGER (5) ,
    ///         msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
    ///         padata          [3] SEQUENCE OF PA-DATA OPTIONAL
    ///                             -- NOTE: not empty --,
    ///         req-body        [4] KDC-REQ-BODY
    /// }
    /// </summary>
    public abstract class KdcRequest : KerberosAsn1Object
    {
        public int ProtocolVersionNumber { get; set; }
        public MessageType MessageType { get; set; }
        public IList<PreAuthenticationData> PaData { get; set; }
        public KdcReqBody Body { get; set; }

        protected KdcRequest(Asn1Identifier id) : base(id) {
            PaData = new List<PreAuthenticationData>();
        }

        protected KdcRequest(Asn1Identifier id, Asn1DecoderProperties props) : this(id)
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
                        // pvno            [1] INTEGER (5) ,
                        var asn1pvno = DecodeAs<Asn1Integer>(props);
                        ProtocolVersionNumber = asn1pvno.IntValue();
                        return asn1pvno;
                    case 2:
                        // msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
                        var asn1msgType = DecodeAs<Asn1Integer>(props);
                        MessageType = (MessageType)asn1msgType.IntValue();
                        return asn1msgType;
                    case 3:
                        //padata          [3] SEQUENCE OF PA-DATA OPTIONAL -- NOTE: not empty --,
                        var paDataSeq = props.DecodeAs<Asn1Sequence>();
                        PaData = paDataSeq.Transform<Asn1Sequence, PreAuthenticationData>(paInput =>
                        {
                            throw new NotImplementedException();
                        });
                        return paDataSeq;
                    case 4:
                        //req-body        [4] KDC-REQ-BODY
                        Body = new KdcReqBody(props);
                        return Body;
                       
                }
            }

            return null;
        }
    }
}
