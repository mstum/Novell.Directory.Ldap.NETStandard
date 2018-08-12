using Novell.Directory.Ldap.Asn1;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    public class TgsRequest : KdcRequest
    {
        // TGS-REQ ::= [APPLICATION 12] KDC-REQ  
        public static readonly Asn1Identifier Id = new Asn1Identifier(Asn1Identifier.Application, true, 12);

        public TgsRequest()
            : base(Id)
        {
        }

        public TgsRequest(Asn1Tagged input, IAsn1Decoder decoder)
            : base(Id, input, decoder)
        {            
        }

        public override void Encode(IAsn1Encoder enc, Stream outRenamed)
        {
            throw new System.NotImplementedException();
        }
    }
}
