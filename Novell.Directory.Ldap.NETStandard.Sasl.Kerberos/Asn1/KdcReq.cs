using Novell.Directory.Ldap.Asn1;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    public abstract class KdcReq : Asn1Sequence
    {
        protected KdcReq(Asn1Identifier id) : base(id)
        {
        }

        protected KdcReq(Asn1Identifier id, int size) : base(id, size)
        {
        }

        protected KdcReq(Asn1Identifier id, Asn1Object[] newContent, int size) : base(id, newContent, size)
        {
        }

        protected KdcReq(Asn1Identifier id, IAsn1Decoder dec, Stream inRenamed, int len) : base(id, dec, inRenamed, len)
        {
        }
    }
}
