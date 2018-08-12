using Novell.Directory.Ldap.Asn1;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// 
    /// </summary>
    /// <remarks>
    /// KRB-ERROR       ::= [APPLICATION 30] SEQUENCE {
    ///         pvno            [0] INTEGER (5),
    ///         msg-type        [1] INTEGER (30),
    ///         ctime           [2] KerberosTime OPTIONAL,
    ///         cusec           [3] Microseconds OPTIONAL,
    ///         stime           [4] KerberosTime,
    ///         susec           [5] Microseconds,
    ///         error-code      [6] Int32,
    ///         crealm          [7] Realm OPTIONAL,
    ///         cname           [8] PrincipalName OPTIONAL,
    ///         realm           [9] Realm -- service realm --,
    ///         sname           [10] PrincipalName -- service name --,
    ///         e-text          [11] KerberosString OPTIONAL,
    ///         e-data          [12] OCTET STRING OPTIONAL
    /// }
    /// </remarks>
    public class KerberosError : KerberosAsn1Object
    {
        public const int Tag = 30;
        public static readonly Asn1Identifier Id = new Asn1Identifier(Asn1Identifier.Application, true, Tag);

        public int ProtocolVersionNumber { get; }
        public MessageType MessageType { get; }
        public DateTime CTime { get; set; }
        public Microseconds? CUsec { get; set; }
        public DateTime STime { get; set; }
        public Microseconds? SUsec { get; set; }
        public int ErrorCode { get; set; }
        public string CRealm { get; set; }
        public PrincipalName CName { get; set; }
        public string ServiceRealm { get; set; }
        public PrincipalName SName { get; set; }
        public string EText { get; set; }
        public byte[] EData { get; set; }

        public KerberosError() : base(Id)
        {
        }

        public KerberosError(Asn1Tagged input, IAsn1Decoder decoder) : this()
        {
            foreach (var item in IterateThroughSequence(input, decoder, contextTagsOnly: true))
            {
                var itemId = item.GetIdentifier();
                var ostring = (Asn1OctetString)item.TaggedValue;
                switch (itemId.Tag)
                {
                    case 0:
                        //         pvno            [0] INTEGER (5),
                        ProtocolVersionNumber = (int)DecodeInteger(ostring, decoder);
                        break;
                    case 1:
                        //         msg-type        [1] INTEGER (30),
                        MessageType = (MessageType)DecodeInteger(ostring, decoder);
                        break;
                    case 2:
                        //         ctime           [2] KerberosTime OPTIONAL,
                        var ctime = ostring.DecodeAs<Asn1GeneralizedTime>(decoder);
                        if (ctime.GeneralizedTime != DateTime.MinValue)
                        {
                            CTime = ctime.GeneralizedTime;
                        }
                        break;
                    case 3:
                        //         cusec           [3] Microseconds OPTIONAL,
                        var cusec = DecodeInteger(ostring, decoder);
                        CUsec = new Microseconds((int)cusec);
                        break;
                    case 4:
                        //         stime           [4] KerberosTime,
                        var stime = ostring.DecodeAs<Asn1GeneralizedTime>(decoder);
                        STime = stime.GeneralizedTime;
                        break;
                    case 5:
                        //         susec           [5] Microseconds,
                        var susec = DecodeInteger(ostring, decoder);
                        SUsec = new Microseconds((int)susec);
                        break;
                    case 6:
                        //         error-code      [6] Int32,
                        // TODO: Make this an Enum
                        ErrorCode = (int)DecodeInteger(ostring, decoder);
                        break;
                    case 7:
                        //         crealm          [7] Realm OPTIONAL,
                        var crealm = ostring.DecodeAs<Asn1GeneralString>(decoder);
                        CRealm = crealm.StringValue();
                        break;
                    case 8:
                        //         cname           [8] PrincipalName OPTIONAL,
                        CName = new PrincipalName(item, decoder);
                        break;
                    case 9:
                        //         realm           [9] Realm -- service realm --,
                        var serviceRealm = ostring.DecodeAs<Asn1GeneralString>(decoder);
                        ServiceRealm = serviceRealm.StringValue();
                        break;
                    case 10:
                        //         sname           [10] PrincipalName -- service name --,
                        SName = new PrincipalName(item, decoder);
                        break;
                    case 11:
                        //         e-text          [11] KerberosString OPTIONAL,
                        var etext = ostring.DecodeAs<Asn1GeneralString>(decoder);
                        EText = etext.StringValue();
                        break;
                    case 12:
                        //         e-data          [12] OCTET STRING OPTIONAL
                        EData = ostring.ByteValue();
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
