using System;
using System.Collections.Generic;
using System.IO;
using Novell.Directory.Ldap.Asn1;

namespace Novell.Directory.Ldap.Sasl.Kerberos
{
    public abstract class KerberosAsn1Object : Asn1Object
    {
        protected KerberosAsn1Object(Asn1Identifier id) : base(id)
        {
        }

        protected static T DecodeAs<T>(Asn1DecoderProperties contentProps) where T : Asn1Object 
            => contentProps.Decoder.Decode(contentProps.Input, null) as T;

        /*
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
        */
    }
}
