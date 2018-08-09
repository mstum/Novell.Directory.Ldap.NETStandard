using Novell.Directory.Ldap.Asn1;
using System.Collections.Generic;
using System.IO;
using Xunit;

namespace Novell.Directory.Ldap.NETStandard.UnitTests
{
    public partial class Asn1Tests
    {
        /// <summary>
        /// Tests for de-/serialization of ASN.1 under Basic Encoding Rules (BER)
        /// </summary>
        public class Ber
        {
            [Fact]
            public void Asn1Null_EncodesProperly()
            {
                IEnumerable<byte> expected = new byte[] { 0x05, 0x00 };

                var ser = new LberEncoder();
                var obj = new Asn1Null();
                using (var ms = new MemoryStream())
                {
                    ser.Encode(obj, ms);
                    var result = ms.ToArray();
                    Assert.Equal(expected, result);
                }
            }

            [Fact]
            public void Asn1Null_DecodesProperly()
            {
                var deser = new LberDecoder();
                var result = deser.Decode(new byte[] { 0x05, 0x00 });
                Assert.NotNull(result);
                Assert.True(result.GetIdentifier().IsSameTagAs(Asn1Null.Id));
                Assert.IsType<Asn1Null>(result);
            }

            [Fact]
            public void Asn1VisibleString_DecodesProperly()
            {
                // Tag + Length + Hello
                var input = new byte[] { 0x1A, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F };

                var deser = new LberDecoder();
                var result = deser.Decode(input);

                Assert.NotNull(result);
                Assert.True(result.GetIdentifier().IsSameTagAs(Asn1VisibleString.Id));
                Assert.IsType<Asn1VisibleString>(result);
            }

            [Fact]
            public void Asn1GeneralizedTime_DecodesProperly()
            {
                // Tag + Length + 20180809143328
                var input = new byte[] { 0x18, 0x0E, 0x32, 0x30, 0x31, 0x38, 0x30, 0x38, 0x30, 0x39, 0x31, 0x34, 0x33, 0x33, 0x32, 0x38 };

                var deser = new LberDecoder();
                var result = deser.Decode(input);

                Assert.NotNull(result);
                Assert.True(result.GetIdentifier().IsSameTagAs(Asn1GeneralizedTime.Id));
                Assert.IsType<Asn1GeneralizedTime>(result);
            }
        }
    }
}
