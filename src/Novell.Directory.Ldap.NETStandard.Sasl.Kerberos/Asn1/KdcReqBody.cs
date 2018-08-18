using System;
using System.IO;
using Novell.Directory.Ldap.Asn1;

namespace Novell.Directory.Ldap.Sasl.Kerberos
{
    /// <summary>
    /// KDC-REQ-BODY    ::= SEQUENCE {
    ///         kdc-options             [0] KDCOptions,
    ///         cname                   [1] PrincipalName OPTIONAL
    ///                                     -- Used only in AS-REQ --,
    ///         realm                   [2] Realm
    ///                                     -- Server's realm
    ///                                     -- Also client's in AS-REQ --,
    ///         sname                   [3] PrincipalName OPTIONAL,
    ///         from                    [4] KerberosTime OPTIONAL,
    ///         till                    [5] KerberosTime,
    ///         rtime                   [6] KerberosTime OPTIONAL,
    ///         nonce                   [7] UInt32,
    ///         etype                   [8] SEQUENCE OF Int32 -- EncryptionType
    ///                                     -- in preference order --,
    ///         addresses               [9] HostAddresses OPTIONAL,
    ///         enc-authorization-data  [10] EncryptedData OPTIONAL
    ///                                     -- AuthorizationData --,
    ///         additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
    ///                                         -- NOTE: not empty
    /// }
    /// </summary>
    public class KdcReqBody : KerberosAsn1Object
    {
        // Padding?
        public KdcOptions KdcOptions { get; set; }

        public PrincipalName CName { get; set; }

        /// <summary>
        /// -- Server's realm
        /// -- Also client's in AS-REQ --
        /// </summary>
        public string Realm { get; set; }

        public PrincipalName SName { get; set; }
        public DateTime? From { get; set; }
        public DateTime Till { get; set; }
        public DateTime? RTime { get; set; }
        public uint Nonce { get; set; }

        /// <summary>
        /// In Preference Order
        /// </summary>
        public EncryptionType[] EncryptionType { get; set; }

        public HostAddress[] Addresses { get; set; }

        public EncryptedData EncAuthorizationData { get; set; }

        public Ticket[] AdditionalTickets { get; set; }


        // KDC-REQ-BODY has no Id of it's own, since it's always part of some object
        public KdcReqBody() : base(Asn1Sequence.Id) {
            EncryptionType = Array.Empty<EncryptionType>();
            Addresses = Array.Empty<HostAddress>();
            AdditionalTickets = Array.Empty<Ticket>();
        }

        public KdcReqBody(Asn1DecoderProperties props) : this()
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
                        // kdc-options             [0] KDCOptions,
                        var kdcOpt = props.DecodeAs<Asn1BitString>();
                        KdcOptions = kdcOpt.ToFlagsEnum<KdcOptions>();
                        return kdcOpt;
                    case 1:
                        // cname                   [1] PrincipalName OPTIONAL -- Used only in AS-REQ --,
                        CName = new PrincipalName(props);
                        return CName;
                    case 2:
                        // realm                   [2] Realm
                        var realm = DecodeAs<Asn1GeneralString>(props);
                        Realm = realm.StringValue();
                        return realm;
                    case 3:
                        // sname                   [3] PrincipalName OPTIONAL,
                        SName = new PrincipalName(props);
                        return SName;
                    case 4:
                        // from                    [4] KerberosTime OPTIONAL,
                        var from = DecodeAs<Asn1GeneralizedTime>(props);
                        if (from.GeneralizedTime != DateTime.MinValue)
                        {
                            From = from.GeneralizedTime;
                        }
                        return from;
                    case 5:
                        // till                    [5] KerberosTime,
                        var till = DecodeAs<Asn1GeneralizedTime>(props);
                        Till = till.GeneralizedTime;
                        return till;
                    case 6:
                        // rtime                   [6] KerberosTime OPTIONAL,
                        var rtime = DecodeAs<Asn1GeneralizedTime>(props);
                        if (rtime.GeneralizedTime != DateTime.MinValue)
                        {
                            RTime = rtime.GeneralizedTime;
                        }
                        return rtime;
                    case 7:
                        // nonce                   [7] UInt32,
                        var asn1nonce = DecodeAs<Asn1Integer>(props);
                        Nonce = (uint)asn1nonce.LongValue();
                        return asn1nonce;
                    case 8:
                        // etype                   [8] SEQUENCE OF Int32 -- EncryptionType
                        var etypeSeq = props.DecodeAs<Asn1Sequence>();
                        EncryptionType = etypeSeq.Transform<Asn1Integer, EncryptionType>(inInt => (EncryptionType)inInt.IntValue());
                        return etypeSeq;
                    case 9:
                        // addresses               [9] HostAddresses OPTIONAL,
                        var addrSeq = props.DecodeAs<Asn1Sequence>();
                        Addresses = addrSeq.Transform<Asn1Sequence, HostAddress>(inSeq =>
                        {
                            throw new NotImplementedException();
                        });
                        return addrSeq;
                    case 10:
                        // enc-authorization-data  [10] EncryptedData OPTIONAL
                        EncAuthorizationData = new EncryptedData(props);
                        return EncAuthorizationData;
                    case 11:
                        // additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
                        var ticketSeq = props.DecodeAs<Asn1Sequence>();
                        AdditionalTickets = ticketSeq.Transform<Asn1Sequence, Ticket>(inSeq =>
                        {
                            throw new NotImplementedException();
                        });
                        return ticketSeq;
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
