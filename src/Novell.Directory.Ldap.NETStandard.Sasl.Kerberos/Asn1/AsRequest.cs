using Novell.Directory.Ldap.Asn1;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    public class AsRequest : KdcRequest
    {
        // AS-REQ          ::= [APPLICATION 10] KDC-REQ
        public static readonly Asn1Identifier Id = new Asn1Identifier(Asn1Identifier.Application, true, 10);

        public AsRequest()
            : base(Id)
        {
        }

        public AsRequest(Asn1Tagged input, IAsn1Decoder decoder)
            : base(Id, input, decoder)
        {            
        }

        public override void Encode(IAsn1Encoder enc, Stream outRenamed)
        {
            throw new System.NotImplementedException();
        }
    }
}
