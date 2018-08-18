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
                var result = deser.Decode(new byte[] { 0x05, 0x00 }, null);
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
                var result = deser.Decode(input, null);

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
                var result = deser.Decode(input, null);

                Assert.NotNull(result);
                Assert.True(result.GetIdentifier().IsSameTagAs(Asn1GeneralizedTime.Id));
                Assert.IsType<Asn1GeneralizedTime>(result);
            }

            [Fact]
            public void Asn1BitString_8Bits_DecodesProperly()
            {
                var input = new byte[] { 0x03, 0x01, 0xFF };
                var deser = new LberDecoder();

                var bitString = deser.Decode(input, null) as Asn1BitString;
                Assert.NotNull(bitString);
                Assert.Equal(8, bitString.NumBits);
                for (int i = 0; i < 8; i++)
                {
                    Assert.True(bitString.IsSet(i), $"bitString[{i}] was not set");
                }
            }

            [Fact]
            public void Asn1BitString_64Bits_DecodesProperly()
            {
                var input = new byte[] { 0x03, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
                var deser = new LberDecoder();

                var bitString = deser.Decode(input, null) as Asn1BitString;
                Assert.NotNull(bitString);
                Assert.Equal(64, bitString.NumBits);
                for (int i = 0; i < 64; i++)
                {
                    Assert.True(bitString.IsSet(i), $"bitString[{i}] was not set");
                }
            }

            [Fact]
            public void Asn1BitString_5Bytes_DecodesProperly()
            {
                var input = new byte[] { 0x03, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
                var deser = new LberDecoder();

                var bitString = deser.Decode(input, null) as Asn1BitString;
                Assert.NotNull(bitString);
                Assert.Equal(40, bitString.NumBits);
                for (int i = 0; i < 40; i++)
                {
                    Assert.True(bitString.IsSet(i), $"bitString[{i}] was not set");
                }
            }

            [Fact]
            public void Asn1BitString_8Bits_ToFlagsEnum_ConvertsProperly()
            {
                var input = new byte[] { 0x03, 0x01, 0b01000101 };
                var deser = new LberDecoder();

                var bitString = deser.Decode(input, null) as Asn1BitString;
                var sbf = bitString.ToFlagsEnum<SByteFlagsEnum>();
                Assert.False(sbf.HasFlag(SByteFlagsEnum.One), "One");
                Assert.True(sbf.HasFlag(SByteFlagsEnum.Two), "Two");
                Assert.False(sbf.HasFlag(SByteFlagsEnum.Four), "Four");
                Assert.False(sbf.HasFlag(SByteFlagsEnum.Eight), "Eight");
                Assert.False(sbf.HasFlag(SByteFlagsEnum.Sixteen), "Sixteen");
                Assert.True(sbf.HasFlag(SByteFlagsEnum.ThirtyTwo), "ThirtyTwo");
                Assert.False(sbf.HasFlag(SByteFlagsEnum.SixtyFour), "SixtyFour");
                Assert.True(sbf.HasFlag(SByteFlagsEnum.OneTwentyEight), "OneTwentyEight");
            }

            [Fact]
            public void Asn1BitString_64Bits_ToFlagsEnum_ConvertsProperly()
            {
                var input = new byte[] { 0x03, 0x08,
                    0b10000001, // Value 1 - 8
                    0b10101010, // Value 9 - 16
                    0b01010101, // Value 17 - 24
                    0b00000000, // Value 25 - 32
                    0b00000000, // Value 33 - 40
                    0b00000000, // Value 41 - 48
                    0b00000000, // Value 49 - 56
                    0b00000001  // Value 57 - 64
                };
                var deser = new LberDecoder();

                var bitString = deser.Decode(input, null) as Asn1BitString;

                var sbf = bitString.ToFlagsEnum<ULongFlagsEnum>();

                Assert.True(sbf.HasFlag(ULongFlagsEnum.Value1), "Flag Value1");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value2), "Flag Value2");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value3), "Flag Value3");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value4), "Flag Value4");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value5), "Flag Value5");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value6), "Flag Value6");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value7), "Flag Value7");
                Assert.True(sbf.HasFlag(ULongFlagsEnum.Value8), "Flag Value8");
                Assert.True(sbf.HasFlag(ULongFlagsEnum.Value9), "Flag Value9");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value10), "Flag Value10");
                Assert.True(sbf.HasFlag(ULongFlagsEnum.Value11), "Flag Value11");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value12), "Flag Value12");
                Assert.True(sbf.HasFlag(ULongFlagsEnum.Value13), "Flag Value13");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value14), "Flag Value14");
                Assert.True(sbf.HasFlag(ULongFlagsEnum.Value15), "Flag Value15");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value16), "Flag Value16");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value17), "Flag Value17");
                Assert.True(sbf.HasFlag(ULongFlagsEnum.Value18), "Flag Value18");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value19), "Flag Value19");
                Assert.True(sbf.HasFlag(ULongFlagsEnum.Value20), "Flag Value20");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value21), "Flag Value21");
                Assert.True(sbf.HasFlag(ULongFlagsEnum.Value22), "Flag Value22");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value23), "Flag Value23");
                Assert.True(sbf.HasFlag(ULongFlagsEnum.Value24), "Flag Value24");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value25), "Flag Value25");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value26), "Flag Value26");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value27), "Flag Value27");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value28), "Flag Value28");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value29), "Flag Value29");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value30), "Flag Value30");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value31), "Flag Value31");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value32), "Flag Value32");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value33), "Flag Value33");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value34), "Flag Value34");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value35), "Flag Value35");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value36), "Flag Value36");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value37), "Flag Value37");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value38), "Flag Value38");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value39), "Flag Value39");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value40), "Flag Value40");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value41), "Flag Value41");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value42), "Flag Value42");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value43), "Flag Value43");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value44), "Flag Value44");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value45), "Flag Value45");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value46), "Flag Value46");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value47), "Flag Value47");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value48), "Flag Value48");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value49), "Flag Value49");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value50), "Flag Value50");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value51), "Flag Value51");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value52), "Flag Value52");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value53), "Flag Value53");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value54), "Flag Value54");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value55), "Flag Value55");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value56), "Flag Value56");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value57), "Flag Value57");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value58), "Flag Value58");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value59), "Flag Value59");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value60), "Flag Value60");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value61), "Flag Value61");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value62), "Flag Value62");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value63), "Flag Value63");
                Assert.True(sbf.HasFlag(ULongFlagsEnum.Value64), "Flag Value64");
            }

            [Fact]
            public void Asn1BitString_5Bytes_ToFlagsEnum_ConvertsProperly()
            {
                var input = new byte[] { 0x03, 0x05,
                    0b10000001, // Value 1 - 8
                    0b10101010, // Value 9 - 16
                    0b01010101, // Value 17 - 24
                    0b00000000, // Value 25 - 32
                    0b00000010  // Value 33 - 40
                };
                var deser = new LberDecoder();

                var bitString = deser.Decode(input, null) as Asn1BitString;

                var sbf = bitString.ToFlagsEnum<ULongFlagsEnum>();

                Assert.True(sbf.HasFlag(ULongFlagsEnum.Value1), "Flag Value1");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value2), "Flag Value2");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value3), "Flag Value3");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value4), "Flag Value4");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value5), "Flag Value5");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value6), "Flag Value6");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value7), "Flag Value7");
                Assert.True(sbf.HasFlag(ULongFlagsEnum.Value8), "Flag Value8");
                Assert.True(sbf.HasFlag(ULongFlagsEnum.Value9), "Flag Value9");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value10), "Flag Value10");
                Assert.True(sbf.HasFlag(ULongFlagsEnum.Value11), "Flag Value11");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value12), "Flag Value12");
                Assert.True(sbf.HasFlag(ULongFlagsEnum.Value13), "Flag Value13");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value14), "Flag Value14");
                Assert.True(sbf.HasFlag(ULongFlagsEnum.Value15), "Flag Value15");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value16), "Flag Value16");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value17), "Flag Value17");
                Assert.True(sbf.HasFlag(ULongFlagsEnum.Value18), "Flag Value18");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value19), "Flag Value19");
                Assert.True(sbf.HasFlag(ULongFlagsEnum.Value20), "Flag Value20");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value21), "Flag Value21");
                Assert.True(sbf.HasFlag(ULongFlagsEnum.Value22), "Flag Value22");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value23), "Flag Value23");
                Assert.True(sbf.HasFlag(ULongFlagsEnum.Value24), "Flag Value24");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value25), "Flag Value25");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value26), "Flag Value26");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value27), "Flag Value27");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value28), "Flag Value28");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value29), "Flag Value29");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value30), "Flag Value30");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value31), "Flag Value31");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value32), "Flag Value32");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value33), "Flag Value33");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value34), "Flag Value34");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value35), "Flag Value35");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value36), "Flag Value36");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value37), "Flag Value37");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value38), "Flag Value38");
                Assert.True(sbf.HasFlag(ULongFlagsEnum.Value39), "Flag Value39");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value40), "Flag Value40");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value41), "Flag Value41");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value42), "Flag Value42");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value43), "Flag Value43");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value44), "Flag Value44");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value45), "Flag Value45");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value46), "Flag Value46");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value47), "Flag Value47");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value48), "Flag Value48");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value49), "Flag Value49");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value50), "Flag Value50");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value51), "Flag Value51");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value52), "Flag Value52");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value53), "Flag Value53");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value54), "Flag Value54");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value55), "Flag Value55");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value56), "Flag Value56");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value57), "Flag Value57");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value58), "Flag Value58");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value59), "Flag Value59");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value60), "Flag Value60");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value61), "Flag Value61");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value62), "Flag Value62");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value63), "Flag Value63");
                Assert.False(sbf.HasFlag(ULongFlagsEnum.Value64), "Flag Value64");
            }
        }
    }
}
