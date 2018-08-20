using Novell.Directory.Ldap.Asn1;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Novell.Directory.Ldap.Sasl.Kerberos
{
    public static class SequenceOfItems
    {
        public static Asn1Object PaDataSequence(Asn1DecoderProperties props)
        {
            var prev = props.ContextDecoder;
            DecodeAsn1Object das = p =>
            {
                var x = p.Identifier;
                return null;
            };
            
            var paDataSeq = props.DecodeAs<Asn1Sequence>(das);

            props.ContextDecoder = prev;
            return paDataSeq;
        }

    }
}
