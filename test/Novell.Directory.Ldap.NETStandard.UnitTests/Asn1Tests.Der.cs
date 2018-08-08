using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace Novell.Directory.Ldap.NETStandard.UnitTests
{
    public partial class Asn1Tests
    {
        /// <summary>
        /// Tests for de-/serialization of ASN.1 under Distinguished Encoding Rules (DER)
        /// </summary>
        /// <remarks>
        /// Kerberos expects DER according to the spec, although it seems that many implementations
        /// use a BER Decoder and thus accept BER as well. (DER is a subset of BER, so any DER Encoded object
        /// is also a valid BER Encoded object, but the same isn't neccessarily true in reverse.)
        /// </remarks>
        public class Der
        {
            [Fact]
            public void Asn1Null_EncodesProperly()
            {
                throw new NotImplementedException();
            }

            [Fact]
            public void Asn1Null_DecodesProperly()
            {
                throw new NotImplementedException();
            }
        }
    }
}
