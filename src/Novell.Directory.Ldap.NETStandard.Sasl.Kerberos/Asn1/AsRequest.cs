using Novell.Directory.Ldap.Asn1;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Kerberos
{
    public class AsRequest : KdcRequest
    {
        // AS-REQ          ::= [APPLICATION 10] KDC-REQ
        public static readonly Asn1Identifier Id = new Asn1Identifier(TagClass.Application, true, 10);

        public AsRequest()
            : base(Id)
        {
        }

        public AsRequest(Asn1DecoderProperties props)
            : base(Id, props)
        {            
        }

        public override void Encode(IAsn1Encoder enc, Stream outRenamed)
        {
            throw new System.NotImplementedException();
        }
    }
}
