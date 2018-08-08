using System;
using System.IO;

namespace Novell.Directory.Ldap.Asn1
{
    public class Asn1DecodingException : IOException
    {
        public Asn1DecodingException()
        {
        }

        public Asn1DecodingException(string message) : base(message)
        {
        }

        public Asn1DecodingException(string message, Exception innerException) : base(message, innerException)
        {
        }

        public Asn1DecodingException(string message, int hresult) : base(message, hresult)
        {
        }
    }
}
