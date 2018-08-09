using Novell.Directory.Ldap.Asn1;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Xunit;

namespace Novell.Directory.Ldap.NETStandard.UnitTests
{
    public partial class Asn1Tests
    {
        [Fact]
        public void Asn1VisibleString_Decode_ValidString()
        {
            var str = "Hello, World!";
            var stringBytes = Encoding.ASCII.GetBytes(str);
            var decoder = new LberDecoder();
            using (var ms = new MemoryStream(stringBytes))
            {
                var vs = new Asn1VisibleString(decoder, ms, stringBytes.Length);
                Assert.Equal(str, vs.StringValue());
                Assert.Equal((IEnumerable<byte>)stringBytes, vs.ByteValue());
            }
        }

        [Fact]
        public void Asn1VisibleString_Decode_InvalidString_Throws()
        {
            var str = "Not allowed: " + (char)0x1A;
            var stringBytes = Encoding.ASCII.GetBytes(str);
            var decoder = new LberDecoder();
            using (var ms = new MemoryStream(stringBytes))
            {
                Assert.Throws<Asn1DecodingException>(() =>
                {
                    var vs = new Asn1VisibleString(decoder, ms, stringBytes.Length);
                });
            }
        }

        [Theory]
        [InlineData(DateTimeKind.Local)]
        [InlineData(DateTimeKind.Utc)]
        public void Asn1GeneralizedTime_Decode_Valid(DateTimeKind dtk)
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
                var gt = new Asn1GeneralizedTime(decoder, ms, stringBytes.Length);

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
        public void Asn1GeneralizedTime_Decode_WithFractionalSecond(DateTimeKind dtk)
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
                var gt = new Asn1GeneralizedTime(decoder, ms, stringBytes.Length);

                var result = gt.GeneralizedTime;
                Assert.Equal(dtk, result.Kind);
                Assert.Equal(2018, result.Year);
                Assert.Equal(8, result.Month);
                Assert.Equal(9, result.Day);
                Assert.Equal(14, result.Hour);
                Assert.Equal(33, result.Minute);
                Assert.Equal(28, result.Second);
                Assert.Equal(321, result.Millisecond);
            }
        }

        [Theory]
        [InlineData(DateTimeKind.Local)]
        [InlineData(DateTimeKind.Utc)]
        public void Asn1GeneralizedTime_Decode_WithLongFractionalSecond(DateTimeKind dtk)
        {
            var str = "20180809143328.32158961521511454554";
            if (dtk == DateTimeKind.Utc)
            {
                str += "Z";
            }

            var stringBytes = Encoding.ASCII.GetBytes(str);
            var decoder = new LberDecoder();
            using (var ms = new MemoryStream(stringBytes))
            {
                var gt = new Asn1GeneralizedTime(decoder, ms, stringBytes.Length);

                var result = gt.GeneralizedTime;
                Assert.Equal(dtk, result.Kind);
                Assert.Equal(2018, result.Year);
                Assert.Equal(8, result.Month);
                Assert.Equal(9, result.Day);
                Assert.Equal(14, result.Hour);
                Assert.Equal(33, result.Minute);
                Assert.Equal(28, result.Second);
                Assert.Equal(322, result.Millisecond);
            }
        }

        [Theory]
        [InlineData(DateTimeKind.Local)]
        [InlineData(DateTimeKind.Utc)]
        public void Asn1GeneralizedTime_Decode_WithFractionalMinute(DateTimeKind dtk)
        {
            // .5 minutes => 30 seconds
            var str = "201808091433.5";
            if (dtk == DateTimeKind.Utc)
            {
                str += "Z";
            }

            var stringBytes = Encoding.ASCII.GetBytes(str);
            var decoder = new LberDecoder();
            using (var ms = new MemoryStream(stringBytes))
            {
                var gt = new Asn1GeneralizedTime(decoder, ms, stringBytes.Length);

                var result = gt.GeneralizedTime;
                Assert.Equal(dtk, result.Kind);
                Assert.Equal(2018, result.Year);
                Assert.Equal(8, result.Month);
                Assert.Equal(9, result.Day);
                Assert.Equal(14, result.Hour);
                Assert.Equal(33, result.Minute);
                Assert.Equal(30, result.Second);
                Assert.Equal(0, result.Millisecond);
            }
        }

        [Theory]
        [InlineData(DateTimeKind.Local)]
        [InlineData(DateTimeKind.Utc)]
        public void Asn1GeneralizedTime_Decode_WithOddFractionalMinute(DateTimeKind dtk)
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
                var gt = new Asn1GeneralizedTime(decoder, ms, stringBytes.Length);

                var result = gt.GeneralizedTime;
                Assert.Equal(dtk, result.Kind);
                Assert.Equal(2018, result.Year);
                Assert.Equal(8, result.Month);
                Assert.Equal(9, result.Day);
                Assert.Equal(14, result.Hour);
                Assert.Equal(33, result.Minute);
                Assert.Equal(26, result.Second);
                Assert.Equal(335, result.Millisecond);
            }
        }

        [Theory]
        [InlineData(DateTimeKind.Local)]
        [InlineData(DateTimeKind.Utc)]
        public void Asn1GeneralizedTime_Decode_WithFractionalHour(DateTimeKind dtk)
        {
            // .5 hours => 30 minutes, 0 seconds, 0 msec
            var str = "2018080914.5";
            if (dtk == DateTimeKind.Utc)
            {
                str += "Z";
            }

            var stringBytes = Encoding.ASCII.GetBytes(str);
            var decoder = new LberDecoder();
            using (var ms = new MemoryStream(stringBytes))
            {
                var gt = new Asn1GeneralizedTime(decoder, ms, stringBytes.Length);

                var result = gt.GeneralizedTime;
                Assert.Equal(dtk, result.Kind);
                Assert.Equal(2018, result.Year);
                Assert.Equal(8, result.Month);
                Assert.Equal(9, result.Day);
                Assert.Equal(14, result.Hour);
                Assert.Equal(30, result.Minute);
                Assert.Equal(0, result.Second);
                Assert.Equal(0, result.Millisecond);
            }
        }

        [Theory]
        [InlineData(DateTimeKind.Local)]
        [InlineData(DateTimeKind.Utc)]
        public void Asn1GeneralizedTime_Decode_WithOddFractionalHour(DateTimeKind dtk)
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
                var gt = new Asn1GeneralizedTime(decoder, ms, stringBytes.Length);

                var result = gt.GeneralizedTime;
                Assert.Equal(dtk, result.Kind);
                Assert.Equal(2018, result.Year);
                Assert.Equal(8, result.Month);
                Assert.Equal(9, result.Day);
                Assert.Equal(14, result.Hour);
                Assert.Equal(26, result.Minute);
                Assert.Equal(20, result.Second);
                Assert.Equal(90, result.Millisecond);
            }
        }
    }
}
