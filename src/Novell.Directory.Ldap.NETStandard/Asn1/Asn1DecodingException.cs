using System;
using System.IO;

namespace Novell.Directory.Ldap.Asn1
{
    public class Asn1DecodingException : IOException
    {
        public Asn1Identifier Identifier { get; }

        public Asn1DecodingException(Asn1Identifier asn1Id = null)
        {
            Identifier = asn1Id?.Clone();
        }

        public Asn1DecodingException(string message, Asn1Identifier asn1Id = null)
            : base(message)
        {
            Identifier = asn1Id?.Clone();
        }

        public Asn1DecodingException(string message, Exception innerException, Asn1Identifier asn1Id = null)
            : base(message, innerException)
        {
            Identifier = asn1Id?.Clone();
        }

        public Asn1DecodingException(string message, int hresult, Asn1Identifier asn1Id = null)
            : base(message, hresult)
        {
            Identifier = asn1Id?.Clone();
        }
    }
}
