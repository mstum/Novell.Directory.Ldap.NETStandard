using Novell.Directory.Ldap.Asn1;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

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
    public abstract class KdcReq : KerberosAsn1Object
    {
        public int ProtocolVersionNumber { get; set; }
        public MessageType MessageType { get; set; }
        // padata          [3] SEQUENCE OF PA-DATA OPTIONAL
        public KdcReqBody Body { get; set; }

        protected KdcReq(Asn1Identifier id) : base(id) { }

        protected KdcReq(Asn1Identifier id, Asn1Tagged input, IAsn1Decoder decoder) : base(id)
        {
            var val = input.TaggedValue as Asn1OctetString;
            var sequence = decoder.Decode(val.ByteValue()) as Asn1Sequence;

            var size = sequence.Size();
            for (int i = 0; i < size; i++)
            {
                var item = sequence.get_Renamed(i) as Asn1Tagged;
                var itemId = item.GetIdentifier();

                if (itemId.IsContext)
                {
                    var ostring = (Asn1OctetString)item.TaggedValue;
                    switch (itemId.Tag)
                    {
                        case 1:
                            using (var ms = new MemoryStream(ostring.ByteValue()))
                            {
                                var pvno = decoder.Decode(ms) as Asn1Integer;
                                ProtocolVersionNumber = pvno.IntValue();
                            }
                            break;
                        case 2:
                            using (var ms = new MemoryStream(ostring.ByteValue()))
                            {
                                var msgType = decoder.Decode(ms) as Asn1Integer;
                                MessageType = (MessageType)msgType.IntValue();
                            }
                            break;
                        case 3:
                            throw new NotImplementedException("TODO: padata [3] SEQUENCE OF PA-DATA OPTIONAL");
                        case 4:
                            Body = new KdcReqBody(item, decoder);
                            break;
                    }
                }
            }
        }
    }
}
