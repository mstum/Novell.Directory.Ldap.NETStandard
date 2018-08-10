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
        // kdc-options             [0] KDCOptions,
        // cname                   [1] PrincipalName OPTIONAL -- Used only in AS-REQ --,

        /// <summary>
        /// -- Server's realm
        /// -- Also client's in AS-REQ --
        /// </summary>
        public string Realm { get; set; }

        // sname                   [3] PrincipalName OPTIONAL,
        public DateTime? From { get; set; }
        public DateTime Till { get; set; }
        public DateTime? RTime { get; set; }
        public uint Nonce { get; set; }
        // etype                   [8] SEQUENCE OF Int32 -- EncryptionType -- in preference order --,
        // addresses               [9] HostAddresses OPTIONAL,
        // enc-authorization-data  [10] EncryptedData OPTIONAL-- AuthorizationData --,
        // additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL -- NOTE: not empty


        // KDC-REQ-BODY has no Id of it's own, since it's always part of some object
        public KdcReqBody() : base(Asn1Sequence.Id) { }

        public KdcReqBody(Asn1Tagged input, IAsn1Decoder decoder) : base(Asn1Sequence.Id)
        {
            foreach (var item in IterateThroughSequence(input, decoder, contextTagsOnly: true))
            {
                var itemId = item.GetIdentifier();

                var ostring = (Asn1OctetString)item.TaggedValue;
                switch (itemId.Tag)
                {
                    case 0:
                        break;
                    case 1:
                        break;
                    case 2:
                        var rs = ostring.DecodeAs<Asn1GeneralString>(decoder);
                        Realm = rs.StringValue();
                        break;
                    case 3:
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
                        break;
                    case 9:
                        break;
                    case 10:
                        break;
                    case 11:
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
