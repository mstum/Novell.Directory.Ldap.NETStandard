using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Novell.Directory.Ldap.Asn1;

namespace Novell.Directory.Ldap.Sasl.Asn1
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

        public KdcReqBody(Asn1Tagged input, IAsn1Decoder decoder) : this()
        {
            foreach (var item in IterateThroughSequence(input, decoder, contextTagsOnly: true))
            {
                var itemId = item.GetIdentifier();
                var ostring = (Asn1OctetString)item.TaggedValue;
                switch (itemId.Tag)
                {
                    case 0:
                        // TODO: Padding? 0x03 0x05 0x00 0x00 0x00 0x00 0x00
                        var kdcOpt = ostring.DecodeAs<Asn1BitString>(decoder);
                        KdcOptions = kdcOpt.ToFlagsEnum<KdcOptions>();
                        break;
                    case 1:
                        CName = new PrincipalName(item, decoder);
                        break;
                    case 2:
                        var rs = ostring.DecodeAs<Asn1GeneralString>(decoder);
                        Realm = rs.StringValue();
                        break;
                    case 3:
                        SName = new PrincipalName(item, decoder);
                        break;
                    case 4:
                        var from = ostring.DecodeAs<Asn1GeneralizedTime>(decoder);
                        if (from.GeneralizedTime != DateTime.MinValue)
                        {
                            From = from.GeneralizedTime;
                        }
                        break;
                    case 5:
                        var till = ostring.DecodeAs<Asn1GeneralizedTime>(decoder);
                        Till = till.GeneralizedTime;
                        break;
                    case 6:
                        var rtime = ostring.DecodeAs<Asn1GeneralizedTime>(decoder);
                        if (rtime.GeneralizedTime != DateTime.MinValue)
                        {
                            RTime = rtime.GeneralizedTime;
                        }
                        RTime = rtime.GeneralizedTime;
                        break;
                    case 7:
                        var nonce = ostring.DecodeAs<Asn1Integer>(decoder);
                        Nonce = (uint)nonce.LongValue();
                        break;
                    case 8:
                        var val = item.TaggedValue as Asn1OctetString;
                        var sequence = decoder.Decode(val.ByteValue()) as Asn1Sequence;

                        EncryptionType = IterateAndTransform(sequence, (ix, asn1) =>
                        {
                            var i = asn1 as Asn1Integer;
                            return (EncryptionType)i.IntValue();
                        });
                        break;
                    case 9:
                        // addresses               [9] HostAddresses OPTIONAL,
                        var addrSeq = item.TaggedValue as Asn1OctetString;
                        var addrSequence = decoder.Decode(addrSeq.ByteValue()) as Asn1Sequence;

                        // TODO: Is this correct?
                        Addresses = IterateAndTransform<HostAddress>(addrSequence, (ix, asn1) =>
                        {
                            var at = asn1 as Asn1Tagged;
                            return new HostAddress(at, decoder);
                        });
                        break;
                    case 10:
                        // enc-authorization-data  [10] EncryptedData OPTIONAL-- AuthorizationData --,
                        EncAuthorizationData = new EncryptedData(item, decoder);
                        break;
                    case 11:
                        // additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL -- NOTE: not empty
                        var addTick = item.TaggedValue as Asn1OctetString;
                        var addTickSeq = decoder.Decode(addTick.ByteValue()) as Asn1Sequence;

                        // TODO: Is this correct?
                        AdditionalTickets = IterateAndTransform(addTickSeq, (ix, asn1) =>
                        {
                            var at = asn1 as Asn1Tagged;
                            return new Ticket(at, decoder);
                        });
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
