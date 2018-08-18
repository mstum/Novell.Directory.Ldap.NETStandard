using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Kerberos
{
    /// <summary>
    /// Ticket          ::= [APPLICATION 1] SEQUENCE {
    ///         tkt-vno         [0] INTEGER (5),
    ///         realm           [1] Realm,
    ///         sname           [2] PrincipalName,
    ///         enc-part        [3] EncryptedData -- EncTicketPart
    /// }
    /// </summary>
    public class Ticket : KerberosAsn1Object
    {
        public const int Tag = 1;
        public static readonly Asn1Identifier Id = new Asn1Identifier(TagClass.Application, true, Tag);

        public int TicketVersionNumber { get; set; }
        public string Realm { get; set; }
        public PrincipalName SName { get; set; }

        /// <summary>
        /// EncTicketPart
        /// </summary>
        public EncryptedData EncPart { get; set; }

        public Ticket()
            : base(Id)
        {
        }

        public Ticket(Asn1DecoderProperties props)
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
                        // tkt-vno         [0] INTEGER (5),
                        var asn1tvno = DecodeAs<Asn1Integer>(props);
                        TicketVersionNumber = asn1tvno.IntValue();
                        return asn1tvno;
                    case 1:
                        // realm           [1] Realm,
                        var realm = DecodeAs<Asn1GeneralString>(props);
                        Realm = realm.StringValue();
                        return realm;
                    case 2:
                        // sname           [2] PrincipalName,
                        SName = new PrincipalName(props);
                        return SName;
                    case 3:
                        // enc-part        [3] EncryptedData -- EncTicketPart
                        EncPart = new EncryptedData(props);
                        return EncPart;
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
