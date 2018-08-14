using Novell.Directory.Ldap.Asn1;
using System.Collections.Generic;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// KDC-REP         ::= SEQUENCE {
    ///         pvno            [0] INTEGER (5),
    ///         msg-type        [1] INTEGER (11 -- AS -- | 13 -- TGS --),
    ///         padata          [2] SEQUENCE OF PA-DATA OPTIONAL
    ///                                 -- NOTE: not empty --,
    ///         crealm          [3] Realm,
    ///         cname           [4] PrincipalName,
    ///         ticket          [5] Ticket,
    ///         enc-part        [6] EncryptedData
    ///                                 -- EncASRepPart or EncTGSRepPart,
    ///                                 -- as appropriate
    /// }
    /// </summary>
    public abstract class KdcResponse : KerberosAsn1Object
    {
        public int ProtocolVersionNumber { get; set; }
        public MessageType MessageType { get; set; }
        public IList<PreAuthenticationData> PaData { get; set; }
        public string CRealm { get; set; }
        public PrincipalName CName { get; set; }
        public Ticket Ticket { get; set; }
        public EncryptedData EncPart { get; set; }

        protected KdcResponse(Asn1Identifier id)
            : base(id)
        {
            PaData = new List<PreAuthenticationData>();
        }

        protected KdcResponse(Asn1Identifier id, Asn1Tagged input, IAsn1Decoder decoder)
            : this(id)
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
                        MessageType = (MessageType)DecodeInteger(ostring, decoder);
                        break;
                    case 2:
                        var paseq = ostring.DecodeAs<Asn1Sequence>(decoder);
                        foreach (var data in IterateThroughSequence(paseq))
                        {
                            PaData.Add(new PreAuthenticationData(data, decoder));
                        }
                        break;
                    case 3:
                        CRealm = DecodeGeneralString(ostring, decoder);
                        break;
                    case 4:
                        CName = new PrincipalName(item, decoder);
                        break;
                    case 5:
                        var ticketAsn1 = ostring.DecodeAs<Asn1Tagged>(decoder);
                        Ticket = new Ticket(ticketAsn1, decoder);
                        break;
                    case 6:
                        EncPart = new EncryptedData(item, decoder);
                        break;
                }
            }
        }
    }
}
