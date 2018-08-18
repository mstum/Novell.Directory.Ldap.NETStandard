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

        public Authenticator(Asn1Tagged input, IAsn1Decoder decoder)
            : this()
        {
            foreach (var item in IterateThroughSequence(input, decoder, contextTagsOnly: true))
            {
                var itemId = item.GetIdentifier();
                var ostring = (Asn1OctetString)item.TaggedValue;
                switch (itemId.Tag)
                {
                    case 0:
                        //         authenticator-vno       [0] INTEGER (5),
                        AuthenticatorVersionNumber = (int)DecodeInteger(ostring, decoder);
                        break;
                    case 1:
                        //         crealm                  [1] Realm,
                        var cr = ostring.DecodeAs<Asn1GeneralString>(decoder);
                        CRealm = cr.StringValue();
                        break;
                    case 2:
                        //         cname                   [2] PrincipalName,
                        var cname = ostring.DecodeAs<Asn1Tagged>(decoder);
                        CName = new PrincipalName(cname, decoder);
                        break;
                    case 3:
                        //         cksum                   [3] Checksum OPTIONAL,
                        var cksum = ostring.DecodeAs<Asn1Tagged>(decoder);
                        Checksum = new Checksum(cksum, decoder);
                        break;
                    case 4:
                        //         cusec                   [4] Microseconds,
                        CUsec = new Microseconds((int)DecodeInteger(ostring, decoder));
                        break;
                    case 5:
                        //         ctime                   [5] KerberosTime,
                        var ctime = ostring.DecodeAs<Asn1GeneralizedTime>(decoder);
                        CTime = ctime.GeneralizedTime;
                        break;
                    case 6:
                        //         subkey                  [6] EncryptionKey OPTIONAL,
                        var ekey = ostring.DecodeAs<Asn1Tagged>(decoder);
                        SubKey = new EncryptionKey(ekey, decoder);
                        break;
                    case 7:
                        //         seq-number              [7] UInt32 OPTIONAL,
                        SeqNumber = (uint)DecodeInteger(ostring, decoder);
                        break;
                    case 8:
                        //         authorization-data      [8] AuthorizationData OPTIONAL
                        AuthorizationData = IterateAndTransform(item, decoder, (ix, asn1) =>
                        {
                            var asn1Tagged = asn1 as Asn1Tagged;
                            return new AuthorizationData(asn1Tagged, decoder);
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

        public override void Encode(IAsn1Encoder enc, Stream outRenamed)
        {
            throw new NotImplementedException();
        }
    }
}
