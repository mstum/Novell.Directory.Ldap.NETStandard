using Novell.Directory.Ldap.Asn1;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Novell.Directory.Ldap.Sasl.Kerberos
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
        public static readonly Asn1Identifier Id = new Asn1Identifier(TagClass.Application, true, Tag);

        public int ProtocolVersionNumber { get; set; }
        public MessageType MessageType { get; set; }
        public DateTime CTime { get; set; }
        public Microseconds? CUsec { get; set; }
        public DateTime STime { get; set; }
        public Microseconds? SUsec { get; set; }
        public KrbErrorCode ErrorCode { get; set; }
        public string CRealm { get; set; }
        public PrincipalName CName { get; set; }
        public string ServiceRealm { get; set; }
        public PrincipalName SName { get; set; }
        public string EText { get; set; }
        public byte[] EData { get; set; }

        public KerberosError() : base(Id)
        {
        }

        public KerberosError(Asn1DecoderProperties props) : base(Id)
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
                        //         pvno            [0] INTEGER (5),
                        var asn1Int = DecodeAs<Asn1Integer>(props);
                        ProtocolVersionNumber = asn1Int.IntValue();
                        return asn1Int;
                    case 1:
                        //         msg-type        [1] INTEGER (30),
                        var asn1MType = DecodeAs<Asn1Integer>(props);
                        MessageType = (MessageType)asn1MType.IntValue();
                        return asn1MType;
                    case 2:
                        //         ctime           [2] KerberosTime OPTIONAL,
                        var ctime = DecodeAs<Asn1GeneralizedTime>(props);
                        if (ctime.GeneralizedTime != DateTime.MinValue)
                        {
                            CTime = ctime.GeneralizedTime;
                        }
                        return ctime;
                    case 3:
                        //         cusec           [3] Microseconds OPTIONAL,
                        var cusec = DecodeAs<Asn1Integer>(props);
                        CUsec = new Microseconds(cusec.IntValue());
                        return cusec;
                    case 4:
                        //         stime           [4] KerberosTime,
                        var stime = DecodeAs<Asn1GeneralizedTime>(props);
                        STime = stime.GeneralizedTime;
                        return stime;
                    case 5:
                        //         susec           [5] Microseconds,
                        var susec = DecodeAs<Asn1Integer>(props);
                        SUsec = new Microseconds(susec.IntValue());
                        return susec;
                    case 6:
                        //         error-code      [6] Int32,
                        var asn1ErrCode = DecodeAs<Asn1Integer>(props);
                        ErrorCode = (KrbErrorCode)asn1ErrCode.IntValue();
                        return asn1ErrCode;
                    case 7:
                        //         crealm          [7] Realm OPTIONAL,
                        var crealm = DecodeAs<Asn1GeneralString>(props);
                        CRealm = crealm.StringValue();
                        return crealm;
                    case 8:
                        //         cname           [8] PrincipalName OPTIONAL,
                        CName = new PrincipalName(props);
                        return CName;
                    case 9:
                        //         realm           [9] Realm -- service realm --,
                        var realm = DecodeAs<Asn1GeneralString>(props);
                        ServiceRealm = realm.StringValue();
                        return realm;
                    case 10:
                        //         sname           [10] PrincipalName -- service name --,
                        SName = new PrincipalName(props);
                        return SName;
                    case 11:
                        //         e-text          [11] KerberosString OPTIONAL,
                        var etext = DecodeAs<Asn1GeneralString>(props);
                        EText = etext.StringValue();
                        return etext;
                    case 12:
                        //         e-data          [12] OCTET STRING OPTIONAL
                        var edata = DecodeAs<Asn1OctetString>(props);
                        EData = edata.ByteValue();
                        return edata;
                }
            }

            return null; // Unhandled item
        }

        public override void Encode(IAsn1Encoder enc, Stream outRenamed)
        {
            throw new NotImplementedException();
        }
    }
}
