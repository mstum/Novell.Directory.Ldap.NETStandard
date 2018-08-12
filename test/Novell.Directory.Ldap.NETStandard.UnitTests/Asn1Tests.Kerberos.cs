using Novell.Directory.Ldap.Asn1;
using Novell.Directory.Ldap.Sasl.Asn1;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Xunit;

namespace Novell.Directory.Ldap.NETStandard.UnitTests
{
    public partial class Asn1Tests
    {
        public class Kerberos
        {
            [Theory]
            [InlineData(DateTimeKind.Local)]
            [InlineData(DateTimeKind.Utc)]
            public void KerberosTime_Decode_Valid(DateTimeKind dtk)
            {
                var str = "20180809143328";
                if (dtk == DateTimeKind.Utc)
                {
                    str += "Z";
                }
                var stringBytes = Encoding.ASCII.GetBytes(str);
                var decoder = new LberDecoder();
                using (var ms = new MemoryStream(stringBytes))
                {
                    var gt = new KerberosTime(decoder, ms, stringBytes.Length);

                    var result = gt.GeneralizedTime;
                    Assert.Equal(dtk, result.Kind);
                    Assert.Equal(2018, result.Year);
                    Assert.Equal(8, result.Month);
                    Assert.Equal(9, result.Day);
                    Assert.Equal(14, result.Hour);
                    Assert.Equal(33, result.Minute);
                    Assert.Equal(28, result.Second);
                    Assert.Equal(0, result.Millisecond);
                }
            }

            [Theory]
            [InlineData(DateTimeKind.Local)]
            [InlineData(DateTimeKind.Utc)]
            public void KerberosTime_Decode_WithFractionalSecond(DateTimeKind dtk)
            {
                var str = "20180809143328.321";
                if (dtk == DateTimeKind.Utc)
                {
                    str += "Z";
                }
                var stringBytes = Encoding.ASCII.GetBytes(str);
                var decoder = new LberDecoder();
                using (var ms = new MemoryStream(stringBytes))
                {
                    var gt = new KerberosTime(decoder, ms, stringBytes.Length);

                    var result = gt.GeneralizedTime;
                    Assert.Equal(dtk, result.Kind);
                    Assert.Equal(2018, result.Year);
                    Assert.Equal(8, result.Month);
                    Assert.Equal(9, result.Day);
                    Assert.Equal(14, result.Hour);
                    Assert.Equal(33, result.Minute);
                    Assert.Equal(28, result.Second);
                    Assert.Equal(0, result.Millisecond);
                }
            }

            [Theory]
            [InlineData(DateTimeKind.Local)]
            [InlineData(DateTimeKind.Utc)]
            public void KerberosTime_Decode_WithOddFractionalMinute(DateTimeKind dtk)
            {
                // .438914 minutes => 26.33484 seconds => 26 Seconds, 334.84 msec => 335 msec
                var str = "201808091433.438914";
                if (dtk == DateTimeKind.Utc)
                {
                    str += "Z";
                }

                var stringBytes = Encoding.ASCII.GetBytes(str);
                var decoder = new LberDecoder();
                using (var ms = new MemoryStream(stringBytes))
                {
                    var gt = new KerberosTime(decoder, ms, stringBytes.Length);

                    var result = gt.GeneralizedTime;
                    Assert.Equal(dtk, result.Kind);
                    Assert.Equal(2018, result.Year);
                    Assert.Equal(8, result.Month);
                    Assert.Equal(9, result.Day);
                    Assert.Equal(14, result.Hour);
                    Assert.Equal(33, result.Minute);
                    Assert.Equal(26, result.Second);
                    Assert.Equal(0, result.Millisecond);
                }
            }

            [Theory]
            [InlineData(DateTimeKind.Local)]
            [InlineData(DateTimeKind.Utc)]
            public void KerberosTime_Decode_WithOddFractionalHour(DateTimeKind dtk)
            {
                // 0.438914 hours => 26.33484 minutes => 26 minutes, 20.0904 seconds => 20 seconds, 90.4 msec => 90 msec
                var str = "2018080914.438914";
                if (dtk == DateTimeKind.Utc)
                {
                    str += "Z";
                }

                var stringBytes = Encoding.ASCII.GetBytes(str);
                var decoder = new LberDecoder();
                using (var ms = new MemoryStream(stringBytes))
                {
                    var gt = new KerberosTime(decoder, ms, stringBytes.Length);

                    var result = gt.GeneralizedTime;
                    Assert.Equal(dtk, result.Kind);
                    Assert.Equal(2018, result.Year);
                    Assert.Equal(8, result.Month);
                    Assert.Equal(9, result.Day);
                    Assert.Equal(14, result.Hour);
                    Assert.Equal(26, result.Minute);
                    Assert.Equal(20, result.Second);
                    Assert.Equal(0, result.Millisecond);
                }
            }

            [Fact]
            public void AsReq_Decode()
            {
                var b = new byte[] { 0x6a, 0x81, 0xa2, 0x30, 0x81, 0x9f, 0xa1, 0x03, 0x02, 0x01, 0x05, 0xa2, 0x03, 0x02, 0x01, 0x0a, 0xa4, 0x81, 0x92, 0x30, 0x81, 0x8f, 0xa0, 0x07, 0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa1, 0x1a, 0x30, 0x18, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x11, 0x30, 0x0f, 0x1b, 0x0d, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x6f, 0x72, 0xa2, 0x14, 0x1b, 0x12, 0x49, 0x4e, 0x54, 0x2e, 0x44, 0x45, 0x56, 0x44, 0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x53, 0x2e, 0x4f, 0x52, 0x47, 0xa3, 0x27, 0x30, 0x25, 0xa0, 0x03, 0x02, 0x01, 0x02, 0xa1, 0x1e, 0x30, 0x1c, 0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 0x1b, 0x12, 0x49, 0x4e, 0x54, 0x2e, 0x44, 0x45, 0x56, 0x44, 0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x53, 0x2e, 0x4f, 0x52, 0x47, 0xa5, 0x11, 0x18, 0x0f, 0x31, 0x39, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0xa7, 0x06, 0x02, 0x04, 0x3a, 0xc4, 0x87, 0x9c, 0xa8, 0x0e, 0x30, 0x0c, 0x02, 0x01, 0x12, 0x02, 0x01, 0x11, 0x02, 0x01, 0x10, 0x02, 0x01, 0x17 };

                var decoder = new LberDecoder();
                var tagged = decoder.Decode(b) as Asn1Tagged;

                var kerbDec = new KerberosDecoder();
                var result = kerbDec.Decode(tagged, decoder) as AsRequest;

                Assert.NotNull(result);
                Assert.True(result.GetIdentifier().IsSameTagAs(AsRequest.Id));
                Assert.IsType<AsRequest>(result);

                Assert.Equal(5, result.ProtocolVersionNumber);
                Assert.Equal(MessageType.KRB_AS_REQ, result.MessageType);
                Assert.NotNull(result.PaData);
                Assert.Equal(0, result.PaData.Count);
                Assert.NotNull(result.Body);

                var body = result.Body;

                Assert.Equal(0u, (uint)body.KdcOptions);
                Assert.Single(body.CName.Name);
                Assert.Equal("Administrator", body.CName.Name[0]);
                Assert.Equal("INT.DEVDOMAINS.ORG", body.Realm);
                Assert.Equal(2, body.SName.Name.Length);
                Assert.Equal("krbtgt", body.SName.Name[0]);
                Assert.Equal("INT.DEVDOMAINS.ORG", body.SName.Name[1]);
                Assert.Null(body.From);
                Assert.Equal(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc), body.Till);
                Assert.Null(body.RTime);
                Assert.Equal(985958300u, body.Nonce);
                Assert.NotNull(body.EncryptionType);
                Assert.Equal(4, body.EncryptionType.Length);
                Assert.Equal((IEnumerable<EncryptionType>)new EncryptionType[] {
                    EncryptionType.AES256_CTS_HMAC_SHA1_96, EncryptionType.AES128_CTS_HMAC_SHA1_96,
                    EncryptionType.DES3_CBC_SHA1_KD, EncryptionType.RC4_HMAC_NT }, body.EncryptionType);
                Assert.NotNull(body.Addresses);
                Assert.NotNull(body.AdditionalTickets);
                Assert.Null(body.EncAuthorizationData);
            }
        }
    }
}
