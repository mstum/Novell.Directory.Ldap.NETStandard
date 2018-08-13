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

                var kerbDec = new KerberosCodec();
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
                Assert.Equal(NameType.NT_PRINCIPAL, body.CName.Type);
                Assert.Equal("Administrator", body.CName.Name[0]);
                Assert.Equal("INT.DEVDOMAINS.ORG", body.Realm);
                Assert.Equal(2, body.SName.Name.Length);
                Assert.Equal(NameType.NT_SRV_INST, body.SName.Type);
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

            [Fact]
            public void AsReq_WithPaData_Decode()
            {
                var bytes = new byte[] { 0x6a, 0x81, 0xf0, 0x30, 0x81, 0xed, 0xa1, 0x03, 0x02, 0x01, 0x05, 0xa2, 0x03, 0x02, 0x01, 0x0a, 0xa3, 0x4c, 0x30, 0x4a, 0x30, 0x48, 0xa1, 0x03, 0x02, 0x01, 0x02, 0xa2, 0x41, 0x04, 0x3f, 0x30, 0x3d, 0xa0, 0x03, 0x02, 0x01, 0x17, 0xa2, 0x36, 0x04, 0x34, 0x1b, 0x7d, 0xc5, 0xf4, 0xdd, 0x05, 0xe5, 0x8f, 0x24, 0x15, 0x5b, 0x81, 0xcc, 0xf1, 0xae, 0xdd, 0xb6, 0x56, 0xf9, 0xdd, 0x5f, 0x99, 0x14, 0x70, 0xdd, 0xa7, 0xc2, 0x79, 0x41, 0xe7, 0x17, 0xe7, 0xce, 0xb1, 0x64, 0x7f, 0xbd, 0xc7, 0x87, 0xae, 0x8e, 0x24, 0xfe, 0xb6, 0x7c, 0xfa, 0xd4, 0x96, 0xa4, 0x40, 0x6a, 0x08, 0xa4, 0x81, 0x92, 0x30, 0x81, 0x8f, 0xa0, 0x07, 0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa1, 0x1a, 0x30, 0x18, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x11, 0x30, 0x0f, 0x1b, 0x0d, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x6f, 0x72, 0xa2, 0x14, 0x1b, 0x12, 0x49, 0x4e, 0x54, 0x2e, 0x44, 0x45, 0x56, 0x44, 0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x53, 0x2e, 0x4f, 0x52, 0x47, 0xa3, 0x27, 0x30, 0x25, 0xa0, 0x03, 0x02, 0x01, 0x02, 0xa1, 0x1e, 0x30, 0x1c, 0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 0x1b, 0x12, 0x49, 0x4e, 0x54, 0x2e, 0x44, 0x45, 0x56, 0x44, 0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x53, 0x2e, 0x4f, 0x52, 0x47, 0xa5, 0x11, 0x18, 0x0f, 0x31, 0x39, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0xa7, 0x06, 0x02, 0x04, 0x20, 0x24, 0xc6, 0x14, 0xa8, 0x0e, 0x30, 0x0c, 0x02, 0x01, 0x12, 0x02, 0x01, 0x11, 0x02, 0x01, 0x10, 0x02, 0x01, 0x17, };

                var decoder = new LberDecoder();
                var tagged = decoder.Decode(bytes) as Asn1Tagged;

                var kerbDec = new KerberosCodec();
                var result = kerbDec.Decode(tagged, decoder) as AsRequest;

                Assert.NotNull(result);
                Assert.True(result.GetIdentifier().IsSameTagAs(AsRequest.Id));
                Assert.IsType<AsRequest>(result);

                Assert.Equal(5, result.ProtocolVersionNumber);
                Assert.Equal(MessageType.KRB_AS_REQ, result.MessageType);
                Assert.NotNull(result.PaData);
                Assert.Single(result.PaData);
                Assert.Equal(2, result.PaData[0].Type);
                Assert.NotNull(result.Body);

                var body = result.Body;

                Assert.Equal(0u, (uint)body.KdcOptions);
                Assert.Single(body.CName.Name);
                Assert.Equal(NameType.NT_PRINCIPAL, body.CName.Type);
                Assert.Equal("Administrator", body.CName.Name[0]);
                Assert.Equal("INT.DEVDOMAINS.ORG", body.Realm);
                Assert.Equal(2, body.SName.Name.Length);
                Assert.Equal(NameType.NT_SRV_INST, body.SName.Type);
                Assert.Equal("krbtgt", body.SName.Name[0]);
                Assert.Equal("INT.DEVDOMAINS.ORG", body.SName.Name[1]);
                Assert.Null(body.From);
                Assert.Equal(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc), body.Till);
                Assert.Null(body.RTime);
                Assert.Equal(539280916u, body.Nonce);
                Assert.NotNull(body.EncryptionType);
                Assert.Equal(4, body.EncryptionType.Length);
                Assert.Equal((IEnumerable<EncryptionType>)new EncryptionType[] {
                    EncryptionType.AES256_CTS_HMAC_SHA1_96, EncryptionType.AES128_CTS_HMAC_SHA1_96,
                    EncryptionType.DES3_CBC_SHA1_KD, EncryptionType.RC4_HMAC_NT }, body.EncryptionType);
                Assert.NotNull(body.Addresses);
                Assert.NotNull(body.AdditionalTickets);
                Assert.Null(body.EncAuthorizationData);
            }

            [Fact]
            public void KerberosError_PreAuthRequired_Decode()
            {
                var bytes = new byte[] { 0x7e, 0x81, 0xa6, 0x30, 0x81, 0xa3, 0xa0, 0x03, 0x02, 0x01, 0x05, 0xa1, 0x03, 0x02, 0x01, 0x1e, 0xa4, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x31, 0x38, 0x30, 0x38, 0x30, 0x36, 0x32, 0x30, 0x33, 0x33, 0x30, 0x35, 0x5a, 0xa5, 0x05, 0x02, 0x03, 0x0d, 0x68, 0xa8, 0xa6, 0x03, 0x02, 0x01, 0x19, 0xa9, 0x14, 0x1b, 0x12, 0x49, 0x4e, 0x54, 0x2e, 0x44, 0x45, 0x56, 0x44, 0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x53, 0x2e, 0x4f, 0x52, 0x47, 0xaa, 0x27, 0x30, 0x25, 0xa0, 0x03, 0x02, 0x01, 0x02, 0xa1, 0x1e, 0x30, 0x1c, 0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 0x1b, 0x12, 0x49, 0x4e, 0x54, 0x2e, 0x44, 0x45, 0x56, 0x44, 0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x53, 0x2e, 0x4f, 0x52, 0x47, 0xac, 0x39, 0x04, 0x37, 0x30, 0x35, 0x30, 0x12, 0xa1, 0x03, 0x02, 0x01, 0x13, 0xa2, 0x0b, 0x04, 0x09, 0x30, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x02, 0x01, 0x17, 0x30, 0x09, 0xa1, 0x03, 0x02, 0x01, 0x02, 0xa2, 0x02, 0x04, 0x00, 0x30, 0x09, 0xa1, 0x03, 0x02, 0x01, 0x10, 0xa2, 0x02, 0x04, 0x00, 0x30, 0x09, 0xa1, 0x03, 0x02, 0x01, 0x0f, 0xa2, 0x02, 0x04, 0x00 };
                var decoder = new LberDecoder();
                var tagged = decoder.Decode(bytes) as Asn1Tagged;

                var kerbDec = new KerberosCodec();
                var result = kerbDec.Decode(tagged, decoder) as KerberosError;

                Assert.NotNull(result);
                Assert.True(result.GetIdentifier().IsSameTagAs(KerberosError.Id));
                Assert.IsType<KerberosError>(result);

                Assert.Equal(5, result.ProtocolVersionNumber);
                Assert.Equal(MessageType.KRB_ERROR, result.MessageType);
                Assert.Equal(KrbErrorCode.KDC_ERR_PREAUTH_REQUIRED, result.ErrorCode);
                Assert.Equal(new DateTime(2018,8,6,20,33,5,DateTimeKind.Utc), result.STime);
                Assert.Equal(878760, result.SUsec);
                Assert.Equal("INT.DEVDOMAINS.ORG", result.ServiceRealm);
                Assert.NotNull(result.SName);
                Assert.Equal(2, result.SName.Name.Length);
                Assert.Equal(NameType.NT_SRV_INST, result.SName.Type);
                Assert.Equal("krbtgt", result.SName.Name[0]);
                Assert.Equal("INT.DEVDOMAINS.ORG", result.SName.Name[1]);
                Assert.NotNull(result.EData);
            }

            [Fact]
            public void KerberosError_ResponseTooBig_Decode()
            {
                var bytes = new byte[] { 0x7e, 0x6a, 0x30, 0x68, 0xa0, 0x03, 0x02, 0x01, 0x05, 0xa1, 0x03, 0x02, 0x01, 0x1e, 0xa4, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x31, 0x38, 0x30, 0x38, 0x30, 0x36, 0x32, 0x30, 0x33, 0x33, 0x30, 0x35, 0x5a, 0xa5, 0x05, 0x02, 0x03, 0x0d, 0xa5, 0x5f, 0xa6, 0x03, 0x02, 0x01, 0x34, 0xa9, 0x14, 0x1b, 0x12, 0x49, 0x4e, 0x54, 0x2e, 0x44, 0x45, 0x56, 0x44, 0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x53, 0x2e, 0x4f, 0x52, 0x47, 0xaa, 0x27, 0x30, 0x25, 0xa0, 0x03, 0x02, 0x01, 0x02, 0xa1, 0x1e, 0x30, 0x1c, 0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 0x1b, 0x12, 0x49, 0x4e, 0x54, 0x2e, 0x44, 0x45, 0x56, 0x44, 0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x53, 0x2e, 0x4f, 0x52, 0x47, };
                var decoder = new LberDecoder();
                var tagged = decoder.Decode(bytes) as Asn1Tagged;

                var kerbDec = new KerberosCodec();
                var result = kerbDec.Decode(tagged, decoder) as KerberosError;

                Assert.NotNull(result);
                Assert.True(result.GetIdentifier().IsSameTagAs(KerberosError.Id));
                Assert.IsType<KerberosError>(result);

                Assert.Equal(5, result.ProtocolVersionNumber);
                Assert.Equal(MessageType.KRB_ERROR, result.MessageType);
                Assert.Equal(KrbErrorCode.KRB_ERR_RESPONSE_TOO_BIG, result.ErrorCode);
                Assert.Equal(new DateTime(2018, 8, 6, 20, 33, 5, DateTimeKind.Utc), result.STime);
                Assert.Equal(894303, result.SUsec);
                Assert.Equal("INT.DEVDOMAINS.ORG", result.ServiceRealm);
                Assert.NotNull(result.SName);
                Assert.Equal(2, result.SName.Name.Length);
                Assert.Equal(NameType.NT_SRV_INST, result.SName.Type);
                Assert.Equal("krbtgt", result.SName.Name[0]);
                Assert.Equal("INT.DEVDOMAINS.ORG", result.SName.Name[1]);
                Assert.Null(result.EData);
            }
        }
    }
}
