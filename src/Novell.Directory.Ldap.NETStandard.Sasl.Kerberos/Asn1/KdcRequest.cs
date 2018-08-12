﻿using Novell.Directory.Ldap.Asn1;
using System.Collections.Generic;

namespace Novell.Directory.Ldap.Sasl.Asn1
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
        public IList<PaData> PaData { get; set; }
        public KdcReqBody Body { get; set; }

        protected KdcRequest(Asn1Identifier id) : base(id) {
            PaData = new List<PaData>();
        }

        protected KdcRequest(Asn1Identifier id, Asn1Tagged input, IAsn1Decoder decoder) : base(id)
        {
            PaData = new List<PaData>();
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
                        MessageType = (MessageType)DecodeInteger(ostring, decoder);
                        break;
                    case 3:
                        var paDataSeq = ostring.DecodeAs<Asn1Sequence>(decoder);
                        foreach (var data in IterateThroughSequence(paDataSeq))
                        {
                            var newPaData = new PaData(data, decoder);
                            PaData.Add(newPaData);
                        }
                        break;
                    case 4:
                        Body = new KdcReqBody(item, decoder);
                        break;
                }
            }
        }
    }
}
