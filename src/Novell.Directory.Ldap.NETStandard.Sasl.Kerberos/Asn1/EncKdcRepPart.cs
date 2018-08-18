using Novell.Directory.Ldap.Asn1;
using System;

namespace Novell.Directory.Ldap.Sasl.Kerberos
{
    /// <summary>
    /// EncKDCRepPart   ::= SEQUENCE {
    ///         key             [0] EncryptionKey,
    ///         last-req        [1] LastReq,
    ///         nonce           [2] UInt32,
    ///         key-expiration  [3] KerberosTime OPTIONAL,
    ///         flags           [4] TicketFlags,
    ///         authtime        [5] KerberosTime,
    ///         starttime       [6] KerberosTime OPTIONAL,
    ///         endtime         [7] KerberosTime,
    ///         renew-till      [8] KerberosTime OPTIONAL,
    ///         srealm          [9] Realm,
    ///         sname           [10] PrincipalName,
    ///         caddr           [11] HostAddresses OPTIONAL
    /// }
    /// </summary>
    public abstract class EncKdcRepPart : KerberosAsn1Object
    {
        public EncryptionKey Key { get; set; }
        public LastReq[] LastReq { get; set; }
        public uint Nonce { get; set; }
        public DateTime? KeyExpiration { get; set; }
        public TicketFlags Flags { get; set; }
        public DateTime AuthTime { get; set; }
        public DateTime? StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public DateTime? RenewTill { get; set; }
        public string SRealm { get; set; }
        public PrincipalName SName { get; set; }
        public HostAddress[] CAddr { get; set; }

        protected EncKdcRepPart(Asn1Identifier id)
            : base(id)
        {
            CAddr = Array.Empty<HostAddress>();
            LastReq = Array.Empty<LastReq>();
        }

        protected EncKdcRepPart(Asn1Identifier id, Asn1DecoderProperties props)
            : this(id)
        {
            foreach (var item in IterateThroughSequence(input, decoder, contextTagsOnly: true))
            {
                var itemId = item.GetIdentifier();
                var ostring = (Asn1OctetString)item.TaggedValue;
                switch (itemId.Tag)
                {
                    case 0:
                        // key             [0] EncryptionKey,
                        Key = new EncryptionKey(item, decoder);
                        break;
                    case 1:
                        // last-req        [1] LastReq,
                        LastReq = IterateAndTransform(item, decoder, (ix, asn1) =>
                        {
                            return new LastReq((Asn1Tagged)asn1, decoder);
                        });
                        break;
                    case 2:
                        // nonce           [2] UInt32,
                        Nonce = (uint)DecodeInteger(ostring, decoder);
                        break;
                    case 3:
                        // key-expiration  [3] KerberosTime OPTIONAL,
                        var keyExpiration = ostring.DecodeAs<Asn1GeneralizedTime>(decoder);
                        if (keyExpiration.GeneralizedTime != DateTime.MinValue)
                        {
                            KeyExpiration = keyExpiration.GeneralizedTime;
                        }
                        break;
                    case 4:
                        // flags           [4] TicketFlags,
                        var ticketOpt = ostring.DecodeAs<Asn1BitString>(decoder);
                        Flags = ticketOpt.ToFlagsEnum<TicketFlags>();
                        break;
                    case 5:
                        // authtime        [5] KerberosTime,
                        var authTime = ostring.DecodeAs<Asn1GeneralizedTime>(decoder);
                        AuthTime = authTime.GeneralizedTime;
                        break;
                    case 6:
                        // starttime       [6] KerberosTime OPTIONAL,
                        var startTime = ostring.DecodeAs<Asn1GeneralizedTime>(decoder);
                        if (startTime.GeneralizedTime != DateTime.MinValue)
                        {
                            StartTime = startTime.GeneralizedTime;
                        }
                        break;
                    case 7:
                        // endtime         [7] KerberosTime,
                        var endTime = ostring.DecodeAs<Asn1GeneralizedTime>(decoder);
                        EndTime = endTime.GeneralizedTime;
                        break;
                    case 8:
                        // renew-till      [8] KerberosTime OPTIONAL,
                        var renewTill = ostring.DecodeAs<Asn1GeneralizedTime>(decoder);
                        if (renewTill.GeneralizedTime != DateTime.MinValue)
                        {
                            RenewTill = renewTill.GeneralizedTime;
                        }
                        break;
                    case 9:
                        // srealm          [9] Realm,
                        var srealm = ostring.DecodeAs<Asn1GeneralString>(decoder);
                        SRealm = srealm.StringValue();
                        break;
                    case 10:
                        // sname           [10] PrincipalName,
                        SName = new PrincipalName(item, decoder);
                        break;
                    case 11:
                        // caddr           [11] HostAddresses OPTIONAL
                        CAddr = IterateAndTransform(item, decoder, (ix, asn1) =>
                        {
                            var at = asn1 as Asn1Tagged;
                            return new HostAddress(at, decoder);
                        });
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
    }
}
