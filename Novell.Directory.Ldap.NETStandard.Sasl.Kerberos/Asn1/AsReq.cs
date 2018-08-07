using Novell.Directory.Ldap.Asn1;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    public class AsReq : KdcReq
    {
        // AS-REQ          ::= [APPLICATION 10] KDC-REQ
        public static readonly Asn1Identifier Id = new Asn1Identifier(Asn1Identifier.Application, true, 10);

        public AsReq()
            : base(Id)
        {
        }

        public AsReq(int size)
            : base(Id, size)
        {
        }

        public AsReq(Asn1Object[] newContent, int size)
            : base(Id, newContent, size)
        {
        }

        public AsReq(IAsn1Decoder dec, Stream inRenamed, int len)
            : base(Id, dec, inRenamed, len)
        {
        }
    }
}
