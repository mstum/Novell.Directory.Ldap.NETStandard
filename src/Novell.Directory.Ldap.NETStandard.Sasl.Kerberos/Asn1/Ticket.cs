using Novell.Directory.Ldap.Asn1;
using System;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Asn1
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
        public static readonly Asn1Identifier Id = new Asn1Identifier(Asn1Identifier.Application, true, Tag);

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

        public Ticket(Asn1Tagged input, IAsn1Decoder decoder)
            : base(Id)
        {
            foreach (var item in IterateThroughSequence(input, decoder, contextTagsOnly: true))
            {
                var itemId = item.GetIdentifier();
                var ostring = (Asn1OctetString)item.TaggedValue;
                switch (itemId.Tag)
                {
                    case 0:
                        TicketVersionNumber = (int)DecodeInteger(ostring, decoder);
                        break;
                    case 1:
                        Realm = DecodeGeneralString(ostring, decoder);
                        break;
                    case 2:
                        SName = new PrincipalName(item, decoder);
                        break;
                    case 3:
                        EncPart = new EncryptedData(item, decoder);
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
