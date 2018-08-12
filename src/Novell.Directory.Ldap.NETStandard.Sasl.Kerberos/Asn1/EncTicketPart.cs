using Novell.Directory.Ldap.Asn1;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// -- Encrypted part of ticket
    /// EncTicketPart   ::= [APPLICATION 3] SEQUENCE {
    ///         flags                   [0] TicketFlags,
    ///         key                     [1] EncryptionKey,
    ///         crealm                  [2] Realm,
    ///         cname                   [3] PrincipalName,
    ///         transited               [4] TransitedEncoding,
    ///         authtime                [5] KerberosTime,
    ///         starttime               [6] KerberosTime OPTIONAL,
    ///         endtime                 [7] KerberosTime,
    ///         renew-till              [8] KerberosTime OPTIONAL,
    ///         caddr                   [9] HostAddresses OPTIONAL,
    ///         authorization-data      [10] AuthorizationData OPTIONAL
    /// }
    /// </summary>
    public class EncTicketPart : KerberosAsn1Object
    {
        public static readonly Asn1Identifier Id = new Asn1Identifier(Asn1Identifier.Application, true, 3);

        public TicketFlags Flags { get; set; }
        public EncryptionKey Key { get; set; }
        public string CRealm { get; set; }
        public PrincipalName CName { get; set; }
        public TransitedEncoding Transited { get; set; }
        public DateTime AuthTime { get; set; }
        public DateTime? StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public DateTime? RenewTill { get; set; }
        public HostAddress[] CAddresses { get; set; }
        public AuthorizationData AuthorizationData { get; set; }

        public EncTicketPart()
            : base(Id)
        {
        }

        public EncTicketPart(Asn1Tagged input, IAsn1Decoder decoder)
            : base(Id)
        {
            foreach (var item in IterateThroughSequence(input, decoder, contextTagsOnly: true))
            {
                var itemId = item.GetIdentifier();
                var ostring = (Asn1OctetString)item.TaggedValue;
                switch (itemId.Tag)
                {
                    case 0:
                        var ticketOpt = ostring.DecodeAs<Asn1BitString>(decoder);
                        Flags = ticketOpt.ToFlagsEnum<TicketFlags>();
                        break;
                    case 1:
                        Key = new EncryptionKey(item, decoder);
                        break;
                    case 2:
                        var crealm = ostring.DecodeAs<Asn1GeneralString>(decoder);
                        CRealm = crealm.StringValue();
                        break;
                    case 3:
                        CName = new PrincipalName(item, decoder);
                        break;
                    case 4:
                        Transited = new TransitedEncoding(item, decoder);
                        break;
                    case 5:
                        var authTime = ostring.DecodeAs<Asn1GeneralizedTime>(decoder);
                        AuthTime = authTime.GeneralizedTime;
                        break;
                    case 6:
                        var startTime = ostring.DecodeAs<Asn1GeneralizedTime>(decoder);
                        if (startTime.GeneralizedTime != DateTime.MinValue)
                        {
                            StartTime = startTime.GeneralizedTime;
                        }
                        break;
                    case 7:
                        var endTime = ostring.DecodeAs<Asn1GeneralizedTime>(decoder);
                        EndTime = endTime.GeneralizedTime;
                        break;
                    case 8:
                        var renewTill = ostring.DecodeAs<Asn1GeneralizedTime>(decoder);
                        if (renewTill.GeneralizedTime != DateTime.MinValue)
                        {
                            RenewTill = renewTill.GeneralizedTime;
                        }
                        break;
                    case 9:
                        var caddrs = item.TaggedValue as Asn1OctetString;
                        var caddrseq = decoder.Decode(caddrs.ByteValue()) as Asn1Sequence;
                        CAddresses = IterateAndTransform(caddrseq, (ix, caddrItem) =>
                        {
                            var itemSeq = caddrItem as Asn1Tagged;
                            return new HostAddress(itemSeq, decoder);
                        });
                        break;
                    case 10:
                        AuthorizationData = new AuthorizationData(item, decoder);
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
