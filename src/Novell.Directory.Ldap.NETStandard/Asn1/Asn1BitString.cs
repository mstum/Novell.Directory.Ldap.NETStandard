using System;
using System.Collections;
using System.IO;
using System.Reflection;

namespace Novell.Directory.Ldap.Asn1
{
    /// <summary>
    /// The first bit in a bit string is called the leading bit. The final bit in a bit string is called the trailing bit.
    /// The leading bit of the bit string is identified by the "number" zero, with succeeding bits having successive values.
    /// 
    /// So forwardable(1) would be:
    /// 0b01000000_00000000_00000000_00000000
    /// = 1073741824 dec.
    /// This is equivalent to <code>1 &lt;&lt; 30</code>.
    /// Or, in this case, 31-1.
    /// </summary>
    public class Asn1BitString : Asn1Object
    {
        /// <summary> ASN.1 BITSTRING tag definition.</summary>
        public const int Tag = 0x03;

        /// <summary>
        ///     ID is added for Optimization.
        ///     ID needs only be one Value for every instance,
        ///     thus we create it only once.
        /// </summary>
        public static readonly Asn1Identifier Id = new Asn1Identifier(TagClass.Universal, false, Tag);

        /// <summary>
        /// So, the size of this BitArray 
        /// </summary>
        private BitArray _bits;

        public Asn1BitString(int len)
            : base(Id)
        {
            _bits = new BitArray(32);
        }

        public Asn1BitString(IAsn1Decoder dec, Stream inRenamed, int len)
            : base(Id)
        {
            Decode(inRenamed, len);
        }

        public Asn1BitString(Asn1Identifier id, IAsn1Decoder dec, Stream inRenamed, int len)
            : base(id)
        {
            Decode(inRenamed, len);
        }

        protected virtual void Decode(Stream inRenamed, int len)
        {
            // bit 0 = "rightmost"/lsb, bit 7 = "leftmost"/msb
            bool IsBitSet(byte b, int bit)
                => ((b & (1 << bit)) != 0);

            var ba = new BitArray(len * 8, false);
            var tmp = new byte[1];
            // TODO: Something is wrong here.

            for (int i = 0; i < len; i++)
            {
                var retVal = inRenamed.Read(tmp, 0, 1);
                if (retVal < 1)
                {
                    throw new Asn1DecodingException("Encountered EOF before the Bit String was fully decoded.");
                }

                var flagByte = tmp[0];

                if (flagByte != 0) // the BitArray defaults to false, so don't loop if we're not setting anything anyway
                {
                    var multi = i * 8;
                    ba[multi + 0] = IsBitSet(flagByte, 7);
                    ba[multi + 1] = IsBitSet(flagByte, 6);
                    ba[multi + 2] = IsBitSet(flagByte, 5);
                    ba[multi + 3] = IsBitSet(flagByte, 4);
                    ba[multi + 4] = IsBitSet(flagByte, 3);
                    ba[multi + 5] = IsBitSet(flagByte, 2);
                    ba[multi + 6] = IsBitSet(flagByte, 1);
                    ba[multi + 7] = IsBitSet(flagByte, 0);
                }
            }

            _bits = ba;
        }


        public override void Encode(IAsn1Encoder enc, Stream outRenamed)
        {
            throw new NotImplementedException();
        }

        public bool IsSet(int ordinal)
            => _bits.Get(ordinal);

        public void Set(int ordinal, bool value)
            => _bits.Set(ordinal, value);

        public int NumBits => _bits.Length;

        /// <summary>
        /// Converts the BitString to an enum with the [Flags] attribute.
        /// 
        /// Note: We are NOT interpreting the bits as a number with some endianness.
        /// We are sticking to the ASN.1 BIT STRING specification that says that
        /// 01000100 means that flag(1) and flag(5) are set - do NOT convert into 0x44/68dec.
        /// 
        /// An enum would be defined like this:
        /// 
        /// [Flags]
        /// public enum MyFlagsEnum
        /// {
        ///     Flag0 = 1 &lt;&lt; 0, // 1 dec
        ///     Flag1 = 1 &lt;&lt; 1, // 2 dec
        ///     Flag2 = 1 &lt;&lt; 2, // 4 dec
        ///     Flag3 = 1 &lt;&lt; 3, // 8 dec
        ///     Flag4 = 1 &lt;&lt; 4, // 16 dec
        ///     Flag5 = 1 &lt;&lt; 5, // 32 dec
        ///     Flag6 = 1 &lt;&lt; 6, // 64 dec
        ///     Flag7 = 1 &lt;&lt; 7  // 128 dec
        /// }
        /// 
        /// Calling ToFlagsEnum for example MyFlagsEnum above will
        /// return an enum with Flag1 | Flag5.
        /// </summary>
        public T ToFlagsEnum<T>() where T : struct
        {
            var type = typeof(T);
            var ti = type.GetTypeInfo();
            if (!ti.IsEnum)
            {
                throw new ArgumentException("The given Type must be an enum, but it is " + type.Name);
            }

            if (ti.GetCustomAttribute<FlagsAttribute>() == null)
            {
                throw new ArgumentException("The given enum Type must be [Flags] enum");
            }


            var ut = Enum.GetUnderlyingType(type);
            bool isSignedEnum = (ut == typeof(long) || ut == typeof(int) || ut == typeof(short) || ut == typeof(sbyte));

            var vals = (T[])Enum.GetValues(type);
            if (isSignedEnum)
            {
                var result = HandleSignedEnum(vals, ut);
                return (T)Enum.ToObject(type, result);
            }
            else
            {
                var result = HandleUnsignedEnum(vals);
                return (T)Enum.ToObject(type, result);
            }
        }

        private ulong HandleUnsignedEnum<T>(T[] vals)
        {
            ulong result = 0;
            foreach (var val in vals)
            {
                var vul = Convert.ToUInt64(val);
                if (vul == 0) continue;

                switch (vul)
                {
                    case 1UL << 0: if (NumBits >= 1 && IsSet(0)) { result = result | vul; } break;
                    case 1UL << 1: if (NumBits >= 2 && IsSet(1)) { result = result | vul; } break;
                    case 1UL << 2: if (NumBits >= 3 && IsSet(2)) { result = result | vul; } break;
                    case 1UL << 3: if (NumBits >= 4 && IsSet(3)) { result = result | vul; } break;
                    case 1UL << 4: if (NumBits >= 5 && IsSet(4)) { result = result | vul; } break;
                    case 1UL << 5: if (NumBits >= 6 && IsSet(5)) { result = result | vul; } break;
                    case 1UL << 6: if (NumBits >= 7 && IsSet(6)) { result = result | vul; } break;
                    case 1UL << 7: if (NumBits >= 8 && IsSet(7)) { result = result | vul; } break;
                    case 1UL << 8: if (NumBits >= 9 && IsSet(8)) { result = result | vul; } break;
                    case 1UL << 9: if (NumBits >= 10 && IsSet(9)) { result = result | vul; } break;
                    case 1UL << 10: if (NumBits >= 11 && IsSet(10)) { result = result | vul; } break;
                    case 1UL << 11: if (NumBits >= 12 && IsSet(11)) { result = result | vul; } break;
                    case 1UL << 12: if (NumBits >= 13 && IsSet(12)) { result = result | vul; } break;
                    case 1UL << 13: if (NumBits >= 14 && IsSet(13)) { result = result | vul; } break;
                    case 1UL << 14: if (NumBits >= 15 && IsSet(14)) { result = result | vul; } break;
                    case 1UL << 15: if (NumBits >= 16 && IsSet(15)) { result = result | vul; } break;
                    case 1UL << 16: if (NumBits >= 17 && IsSet(16)) { result = result | vul; } break;
                    case 1UL << 17: if (NumBits >= 18 && IsSet(17)) { result = result | vul; } break;
                    case 1UL << 18: if (NumBits >= 19 && IsSet(18)) { result = result | vul; } break;
                    case 1UL << 19: if (NumBits >= 20 && IsSet(19)) { result = result | vul; } break;
                    case 1UL << 20: if (NumBits >= 21 && IsSet(20)) { result = result | vul; } break;
                    case 1UL << 21: if (NumBits >= 22 && IsSet(21)) { result = result | vul; } break;
                    case 1UL << 22: if (NumBits >= 23 && IsSet(22)) { result = result | vul; } break;
                    case 1UL << 23: if (NumBits >= 24 && IsSet(23)) { result = result | vul; } break;
                    case 1UL << 24: if (NumBits >= 25 && IsSet(24)) { result = result | vul; } break;
                    case 1UL << 25: if (NumBits >= 26 && IsSet(25)) { result = result | vul; } break;
                    case 1UL << 26: if (NumBits >= 27 && IsSet(26)) { result = result | vul; } break;
                    case 1UL << 27: if (NumBits >= 28 && IsSet(27)) { result = result | vul; } break;
                    case 1UL << 28: if (NumBits >= 29 && IsSet(28)) { result = result | vul; } break;
                    case 1UL << 29: if (NumBits >= 30 && IsSet(29)) { result = result | vul; } break;
                    case 1UL << 30: if (NumBits >= 31 && IsSet(30)) { result = result | vul; } break;
                    case 1UL << 31: if (NumBits >= 32 && IsSet(31)) { result = result | vul; } break;
                    case 1UL << 32: if (NumBits >= 33 && IsSet(32)) { result = result | vul; } break;
                    case 1UL << 33: if (NumBits >= 34 && IsSet(33)) { result = result | vul; } break;
                    case 1UL << 34: if (NumBits >= 35 && IsSet(34)) { result = result | vul; } break;
                    case 1UL << 35: if (NumBits >= 36 && IsSet(35)) { result = result | vul; } break;
                    case 1UL << 36: if (NumBits >= 37 && IsSet(36)) { result = result | vul; } break;
                    case 1UL << 37: if (NumBits >= 38 && IsSet(37)) { result = result | vul; } break;
                    case 1UL << 38: if (NumBits >= 39 && IsSet(38)) { result = result | vul; } break;
                    case 1UL << 39: if (NumBits >= 40 && IsSet(39)) { result = result | vul; } break;
                    case 1UL << 40: if (NumBits >= 41 && IsSet(40)) { result = result | vul; } break;
                    case 1UL << 41: if (NumBits >= 42 && IsSet(41)) { result = result | vul; } break;
                    case 1UL << 42: if (NumBits >= 43 && IsSet(42)) { result = result | vul; } break;
                    case 1UL << 43: if (NumBits >= 44 && IsSet(43)) { result = result | vul; } break;
                    case 1UL << 44: if (NumBits >= 45 && IsSet(44)) { result = result | vul; } break;
                    case 1UL << 45: if (NumBits >= 46 && IsSet(45)) { result = result | vul; } break;
                    case 1UL << 46: if (NumBits >= 47 && IsSet(46)) { result = result | vul; } break;
                    case 1UL << 47: if (NumBits >= 48 && IsSet(47)) { result = result | vul; } break;
                    case 1UL << 48: if (NumBits >= 49 && IsSet(48)) { result = result | vul; } break;
                    case 1UL << 49: if (NumBits >= 50 && IsSet(49)) { result = result | vul; } break;
                    case 1UL << 50: if (NumBits >= 51 && IsSet(50)) { result = result | vul; } break;
                    case 1UL << 51: if (NumBits >= 52 && IsSet(51)) { result = result | vul; } break;
                    case 1UL << 52: if (NumBits >= 53 && IsSet(52)) { result = result | vul; } break;
                    case 1UL << 53: if (NumBits >= 54 && IsSet(53)) { result = result | vul; } break;
                    case 1UL << 54: if (NumBits >= 55 && IsSet(54)) { result = result | vul; } break;
                    case 1UL << 55: if (NumBits >= 56 && IsSet(55)) { result = result | vul; } break;
                    case 1UL << 56: if (NumBits >= 57 && IsSet(56)) { result = result | vul; } break;
                    case 1UL << 57: if (NumBits >= 58 && IsSet(57)) { result = result | vul; } break;
                    case 1UL << 58: if (NumBits >= 59 && IsSet(58)) { result = result | vul; } break;
                    case 1UL << 59: if (NumBits >= 60 && IsSet(59)) { result = result | vul; } break;
                    case 1UL << 60: if (NumBits >= 61 && IsSet(60)) { result = result | vul; } break;
                    case 1UL << 61: if (NumBits >= 62 && IsSet(61)) { result = result | vul; } break;
                    case 1UL << 62: if (NumBits >= 63 && IsSet(62)) { result = result | vul; } break;
                    case 1UL << 63: if (NumBits >= 64 && IsSet(63)) { result = result | vul; } break;
                }
            }
            return result;
        }

        private long HandleSignedEnum<T>(T[] vals, Type underlyingType)
        {
            long result = 0;
            foreach (var val in vals)
            {
                long vul = Convert.ToInt64(val);
                if (vul == 0) continue;

                // Because the exact numeric type can vary, we have to "normalize" it.
                // For example, an sbyte value of -1 looks like 0b10000000 and needs to become 128
                if (vul < 0 && underlyingType != typeof(long))
                {
                    if (underlyingType == typeof(sbyte))
                    {
                        vul = (byte)vul;
                    }
                    else if (underlyingType == typeof(short))
                    {
                        vul = (short)vul;
                    }
                    else if (underlyingType == typeof(int))
                    {
                        vul = (int)vul;
                    }
                }

                switch (vul)
                {
                    case 1L << 0: if (NumBits >= 1 && IsSet(0)) { result = result | vul; } break;
                    case 1L << 1: if (NumBits >= 2 && IsSet(1)) { result = result | vul; } break;
                    case 1L << 2: if (NumBits >= 3 && IsSet(2)) { result = result | vul; } break;
                    case 1L << 3: if (NumBits >= 4 && IsSet(3)) { result = result | vul; } break;
                    case 1L << 4: if (NumBits >= 5 && IsSet(4)) { result = result | vul; } break;
                    case 1L << 5: if (NumBits >= 6 && IsSet(5)) { result = result | vul; } break;
                    case 1L << 6: if (NumBits >= 7 && IsSet(6)) { result = result | vul; } break;
                    case 1L << 7: if (NumBits >= 8 && IsSet(7)) { result = result | vul; } break;
                    case 1L << 8: if (NumBits >= 9 && IsSet(8)) { result = result | vul; } break;
                    case 1L << 9: if (NumBits >= 10 && IsSet(9)) { result = result | vul; } break;
                    case 1L << 10: if (NumBits >= 11 && IsSet(10)) { result = result | vul; } break;
                    case 1L << 11: if (NumBits >= 12 && IsSet(11)) { result = result | vul; } break;
                    case 1L << 12: if (NumBits >= 13 && IsSet(12)) { result = result | vul; } break;
                    case 1L << 13: if (NumBits >= 14 && IsSet(13)) { result = result | vul; } break;
                    case 1L << 14: if (NumBits >= 15 && IsSet(14)) { result = result | vul; } break;
                    case 1L << 15: if (NumBits >= 16 && IsSet(15)) { result = result | vul; } break;
                    case 1L << 16: if (NumBits >= 17 && IsSet(16)) { result = result | vul; } break;
                    case 1L << 17: if (NumBits >= 18 && IsSet(17)) { result = result | vul; } break;
                    case 1L << 18: if (NumBits >= 19 && IsSet(18)) { result = result | vul; } break;
                    case 1L << 19: if (NumBits >= 20 && IsSet(19)) { result = result | vul; } break;
                    case 1L << 20: if (NumBits >= 21 && IsSet(20)) { result = result | vul; } break;
                    case 1L << 21: if (NumBits >= 22 && IsSet(21)) { result = result | vul; } break;
                    case 1L << 22: if (NumBits >= 23 && IsSet(22)) { result = result | vul; } break;
                    case 1L << 23: if (NumBits >= 24 && IsSet(23)) { result = result | vul; } break;
                    case 1L << 24: if (NumBits >= 25 && IsSet(24)) { result = result | vul; } break;
                    case 1L << 25: if (NumBits >= 26 && IsSet(25)) { result = result | vul; } break;
                    case 1L << 26: if (NumBits >= 27 && IsSet(26)) { result = result | vul; } break;
                    case 1L << 27: if (NumBits >= 28 && IsSet(27)) { result = result | vul; } break;
                    case 1L << 28: if (NumBits >= 29 && IsSet(28)) { result = result | vul; } break;
                    case 1L << 29: if (NumBits >= 30 && IsSet(29)) { result = result | vul; } break;
                    case 1L << 30: if (NumBits >= 31 && IsSet(30)) { result = result | vul; } break;
                    case 1L << 31: if (NumBits >= 32 && IsSet(31)) { result = result | vul; } break;
                    case 1L << 32: if (NumBits >= 33 && IsSet(32)) { result = result | vul; } break;
                    case 1L << 33: if (NumBits >= 34 && IsSet(33)) { result = result | vul; } break;
                    case 1L << 34: if (NumBits >= 35 && IsSet(34)) { result = result | vul; } break;
                    case 1L << 35: if (NumBits >= 36 && IsSet(35)) { result = result | vul; } break;
                    case 1L << 36: if (NumBits >= 37 && IsSet(36)) { result = result | vul; } break;
                    case 1L << 37: if (NumBits >= 38 && IsSet(37)) { result = result | vul; } break;
                    case 1L << 38: if (NumBits >= 39 && IsSet(38)) { result = result | vul; } break;
                    case 1L << 39: if (NumBits >= 40 && IsSet(39)) { result = result | vul; } break;
                    case 1L << 40: if (NumBits >= 41 && IsSet(40)) { result = result | vul; } break;
                    case 1L << 41: if (NumBits >= 42 && IsSet(41)) { result = result | vul; } break;
                    case 1L << 42: if (NumBits >= 43 && IsSet(42)) { result = result | vul; } break;
                    case 1L << 43: if (NumBits >= 44 && IsSet(43)) { result = result | vul; } break;
                    case 1L << 44: if (NumBits >= 45 && IsSet(44)) { result = result | vul; } break;
                    case 1L << 45: if (NumBits >= 46 && IsSet(45)) { result = result | vul; } break;
                    case 1L << 46: if (NumBits >= 47 && IsSet(46)) { result = result | vul; } break;
                    case 1L << 47: if (NumBits >= 48 && IsSet(47)) { result = result | vul; } break;
                    case 1L << 48: if (NumBits >= 49 && IsSet(48)) { result = result | vul; } break;
                    case 1L << 49: if (NumBits >= 50 && IsSet(49)) { result = result | vul; } break;
                    case 1L << 50: if (NumBits >= 51 && IsSet(50)) { result = result | vul; } break;
                    case 1L << 51: if (NumBits >= 52 && IsSet(51)) { result = result | vul; } break;
                    case 1L << 52: if (NumBits >= 53 && IsSet(52)) { result = result | vul; } break;
                    case 1L << 53: if (NumBits >= 54 && IsSet(53)) { result = result | vul; } break;
                    case 1L << 54: if (NumBits >= 55 && IsSet(54)) { result = result | vul; } break;
                    case 1L << 55: if (NumBits >= 56 && IsSet(55)) { result = result | vul; } break;
                    case 1L << 56: if (NumBits >= 57 && IsSet(56)) { result = result | vul; } break;
                    case 1L << 57: if (NumBits >= 58 && IsSet(57)) { result = result | vul; } break;
                    case 1L << 58: if (NumBits >= 59 && IsSet(58)) { result = result | vul; } break;
                    case 1L << 59: if (NumBits >= 60 && IsSet(59)) { result = result | vul; } break;
                    case 1L << 60: if (NumBits >= 61 && IsSet(60)) { result = result | vul; } break;
                    case 1L << 61: if (NumBits >= 62 && IsSet(61)) { result = result | vul; } break;
                    case 1L << 62: if (NumBits >= 63 && IsSet(62)) { result = result | vul; } break;
                    case 1L << 63: if (NumBits >= 64 && IsSet(63)) { result = result | vul; } break;
                }
            }
            return result;
        }

        public override string ToString()
        {
            var chars = new char[NumBits];
            for (int i = 0; i < NumBits; i++)
            {
                chars[i] = IsSet(i) ? '1' : '0';
            }

            return base.ToString() + "BIT STRING: " + new string(chars);
        }
    }
}
