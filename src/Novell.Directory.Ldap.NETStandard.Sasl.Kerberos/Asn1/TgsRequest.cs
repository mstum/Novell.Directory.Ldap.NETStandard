using Novell.Directory.Ldap.Asn1;
using System.IO;

namespace Novell.Directory.Ldap.Sasl.Kerberos
{
    public class TgsRequest : KdcRequest
    {
        // TGS-REQ ::= [APPLICATION 12] KDC-REQ  
        public static readonly Asn1Identifier Id = new Asn1Identifier(TagClass.Application, true, 12);

        public TgsRequest()
            : base(Id)
        {
        }

        public TgsRequest(Asn1DecoderProperties props)
            : base(Id, props)
        {            
        }

        public override void Encode(IAsn1Encoder enc, Stream outRenamed)
        {
            throw new System.NotImplementedException();
        }
    }
}
