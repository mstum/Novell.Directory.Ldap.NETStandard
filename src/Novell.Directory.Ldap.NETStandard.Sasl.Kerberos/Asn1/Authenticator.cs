using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Kerberos
{
    /// <summary>
    /// -- Unencrypted authenticator
    /// Authenticator   ::= [APPLICATION 2] SEQUENCE  {
    ///         authenticator-vno       [0] INTEGER (5),
    ///         crealm                  [1] Realm,
    ///         cname                   [2] PrincipalName,
    ///         cksum                   [3] Checksum OPTIONAL,
    ///         cusec                   [4] Microseconds,
    ///         ctime                   [5] KerberosTime,
    ///         subkey                  [6] EncryptionKey OPTIONAL,
    ///         seq-number              [7] UInt32 OPTIONAL,
    ///         authorization-data      [8] AuthorizationData OPTIONAL
    /// }
    /// </summary>
    public class Authenticator : KerberosAsn1Object
    {
        public static readonly Asn1Identifier Id = new Asn1Identifier(TagClass.Application, true, 2);

        public int AuthenticatorVersionNumber { get; set; }
        public string CRealm { get; set; }
        public PrincipalName CName { get; set; }
        public Checksum Checksum { get; set; }
        public Microseconds CUsec { get; set; }
        public DateTime CTime { get; set; }
        public EncryptionKey SubKey { get; set; }
        public uint SeqNumber { get; set; }
        public AuthorizationData[] AuthorizationData { get; set; }

        public Authenticator()
            : base(Id)
        {
            AuthorizationData = Array.Empty<AuthorizationData>();
        }

        public Authenticator(Asn1DecoderProperties props)
            : this()
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
                        //         authenticator-vno       [0] INTEGER (5),
                        var asn1avno = DecodeAs<Asn1Integer>(props);
                        AuthenticatorVersionNumber = asn1avno.IntValue();
                        return asn1avno;
                    case 1:
                        //         crealm                  [1] Realm,
                        var crealm = DecodeAs<Asn1GeneralString>(props);
                        CRealm = crealm.StringValue();
                        return crealm;
                    case 2:
                        //         cname                   [2] PrincipalName,
                        CName = new PrincipalName(props);
                        return CName;
                    case 3:
                        //         cksum                   [3] Checksum OPTIONAL,
                        Checksum = new Checksum(props);
                        return Checksum;
                    case 4:
                        //         cusec                   [4] Microseconds,
                        var cusec = DecodeAs<Asn1Integer>(props);
                        CUsec = new Microseconds(cusec.IntValue());
                        return cusec;
                    case 5:
                        //         ctime                   [5] KerberosTime,
                        var ctime = DecodeAs<Asn1GeneralizedTime>(props);
                        CTime = ctime.GeneralizedTime;
                        return ctime;
                    case 6:
                        //         subkey                  [6] EncryptionKey OPTIONAL,
                        SubKey = new EncryptionKey(props);
                        return SubKey;
                    case 7:
                        //         seq-number              [7] UInt32 OPTIONAL,
                        var asn1seqno = DecodeAs<Asn1Integer>(props);
                        SeqNumber = (uint)asn1seqno.LongValue();
                        return asn1seqno;
                    case 8:
                        //         authorization-data      [8] AuthorizationData OPTIONAL
                        var authDataSeq = props.DecodeAs<Asn1Sequence>();
                        AuthorizationData = authDataSeq.Transform<Asn1Sequence, AuthorizationData>(inSeq =>
                        {
                            throw new NotImplementedException();
                        });
                        return authDataSeq;
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
