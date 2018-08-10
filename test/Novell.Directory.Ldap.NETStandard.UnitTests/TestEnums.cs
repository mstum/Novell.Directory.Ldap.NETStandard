using System;
using System.Collections.Generic;
using System.Text;

namespace Novell.Directory.Ldap.NETStandard.UnitTests
{
    public enum IntEnum : int
    {
        Reserved = 0,
        Forwardable = 1 << (31 - 1),
        Forwarded = 1 << (31 - 2),
        Proxiable = 1 << (31 - 3),
        Proxy = 1 << (31 - 4),
        AllowPostDate = 1 << (31 - 5),
        PostDated = 1 << (31 - 6),
        Unused7 = 1 << (31 - 7),

        Renewable = 1 << (31 - 8),
        Unused9 = 1 << (31 - 9),
        Unused10 = 1 << (31 - 10),
        OptHardwareAuth = 1 << (31 - 11),
        Unused12 = 1 << (31 - 12),
        Unused13 = 1 << (31 - 13),
        ConstrainedDelegation = 1 << (31 - 14),
        Canonicalize = 1 << (31 - 15), // added in RFC 6806

        RequestAnonymous = 1 << (31 - 16), // added in RFC 6112 / 8062
        Unused17 = 1 << (31 - 17),
        Unused18 = 1 << (31 - 18),
        Unused19 = 1 << (31 - 19),
        Unused20 = 1 << (31 - 20),
        Unused21 = 1 << (31 - 21),
        Unused22 = 1 << (31 - 22),

        Unused23 = 1 << (31 - 23),
        Unused24 = 1 << (31 - 24),
        Unused25 = 1 << (31 - 25),
        DisableTransitedCheck = 1 << (31 - 26), // added in RFC 4120
        RenewableOk = 1 << (31 - 27),
        EncTicketInSKey = 1 << (31 - 28),
        Unused29 = 1 << (31 - 29),
        Renew = 1 << (31 - 30),
        Validate = 1 << (31 - 31),
    }

    [Flags]
    public enum IntFlagsEnum : int
    {
        Reserved = 0,
        Forwardable = 1 << (31 - 1),
        Forwarded = 1 << (31 - 2),
        Proxiable = 1 << (31 - 3),
        Proxy = 1 << (31 - 4),
        AllowPostDate = 1 << (31 - 5),
        PostDated = 1 << (31 - 6),
        Unused7 = 1 << (31 - 7),

        Renewable = 1 << (31 - 8),
        Unused9 = 1 << (31 - 9),
        Unused10 = 1 << (31 - 10),
        OptHardwareAuth = 1 << (31 - 11),
        Unused12 = 1 << (31 - 12),
        Unused13 = 1 << (31 - 13),
        ConstrainedDelegation = 1 << (31 - 14),
        Canonicalize = 1 << (31 - 15), // added in RFC 6806

        RequestAnonymous = 1 << (31 - 16), // added in RFC 6112 / 8062
        Unused17 = 1 << (31 - 17),
        Unused18 = 1 << (31 - 18),
        Unused19 = 1 << (31 - 19),
        Unused20 = 1 << (31 - 20),
        Unused21 = 1 << (31 - 21),
        Unused22 = 1 << (31 - 22),

        Unused23 = 1 << (31 - 23),
        Unused24 = 1 << (31 - 24),
        Unused25 = 1 << (31 - 25),
        DisableTransitedCheck = 1 << (31 - 26), // added in RFC 4120
        RenewableOk = 1 << (31 - 27),
        EncTicketInSKey = 1 << (31 - 28),
        Unused29 = 1 << (31 - 29),
        Renew = 1 << (31 - 30),
        Validate = 1 << (31 - 31),
    }

    public enum SByteEnum : sbyte
    {
        Zero = 0,
        One = 1,
        Two = 2,
        Four = 4,
        Eight = 8,
        Sixteen = 16,
        ThirtyTwo = 32,
        SixtoFour = 64,
        OneTwentyEight = unchecked((sbyte)128)
    }

    [Flags]
    public enum SByteFlagsEnum : sbyte
    {
        Zero = 0,
        One = 1,
        Two = 2,
        Four = 4,
        Eight = 8,
        Sixteen = 16,
        ThirtyTwo = 32,
        SixtyFour = 64,
        OneTwentyEight = unchecked((sbyte)128)
    }

    public enum ULongEnum : ulong
    {
        Value1 = 1,
        Value2 = 2,
        Value3 = 4,
        Value4 = 8,
        Value5 = 16,
        Value6 = 32,
        Value7 = 64,
        Value8 = 128,
        Value9 = 256,
        Value10 = 512,
        Value11 = 1024,
        Value12 = 2048,
        Value13 = 4096,
        Value14 = 8192,
        Value15 = 16384,
        Value16 = 32768,
        Value17 = 65536,
        Value18 = 131072,
        Value19 = 262144,
        Value20 = 524288,
        Value21 = 1048576,
        Value22 = 2097152,
        Value23 = 4194304,
        Value24 = 8388608,
        Value25 = 16777216,
        Value26 = 33554432,
        Value27 = 67108864,
        Value28 = 134217728,
        Value29 = 268435456,
        Value30 = 536870912,
        Value31 = 1073741824,
        Value32 = 2147483648,
        Value33 = 4294967296,
        Value34 = 8589934592,
        Value35 = 17179869184,
        Value36 = 34359738368,
        Value37 = 68719476736,
        Value38 = 137438953472,
        Value39 = 274877906944,
        Value40 = 549755813888,
        Value41 = 1099511627776,
        Value42 = 2199023255552,
        Value43 = 4398046511104,
        Value44 = 8796093022208,
        Value45 = 17592186044416,
        Value46 = 35184372088832,
        Value47 = 70368744177664,
        Value48 = 140737488355328,
        Value49 = 281474976710656,
        Value50 = 562949953421312,
        Value51 = 1125899906842624,
        Value52 = 2251799813685248,
        Value53 = 4503599627370496,
        Value54 = 9007199254740992,
        Value55 = 18014398509481984,
        Value56 = 36028797018963968,
        Value57 = 72057594037927936,
        Value58 = 144115188075855872,
        Value59 = 288230376151711744,
        Value60 = 576460752303423488,
        Value61 = 1152921504606846976,
        Value62 = 2305843009213693952,
        Value63 = 4611686018427387904,
        Value64 = 9223372036854775808
    }

    [Flags]
    public enum ULongFlagsEnum : ulong
    {
        Value1 = 1,
        Value2 = 2,
        Value3 = 4,
        Value4 = 8,
        Value5 = 16,
        Value6 = 32,
        Value7 = 64,
        Value8 = 128,
        Value9 = 256,
        Value10 = 512,
        Value11 = 1024,
        Value12 = 2048,
        Value13 = 4096,
        Value14 = 8192,
        Value15 = 16384,
        Value16 = 32768,
        Value17 = 65536,
        Value18 = 131072,
        Value19 = 262144,
        Value20 = 524288,
        Value21 = 1048576,
        Value22 = 2097152,
        Value23 = 4194304,
        Value24 = 8388608,
        Value25 = 16777216,
        Value26 = 33554432,
        Value27 = 67108864,
        Value28 = 134217728,
        Value29 = 268435456,
        Value30 = 536870912,
        Value31 = 1073741824,
        Value32 = 2147483648,
        Value33 = 4294967296,
        Value34 = 8589934592,
        Value35 = 17179869184,
        Value36 = 34359738368,
        Value37 = 68719476736,
        Value38 = 137438953472,
        Value39 = 274877906944,
        Value40 = 549755813888,
        Value41 = 1099511627776,
        Value42 = 2199023255552,
        Value43 = 4398046511104,
        Value44 = 8796093022208,
        Value45 = 17592186044416,
        Value46 = 35184372088832,
        Value47 = 70368744177664,
        Value48 = 140737488355328,
        Value49 = 281474976710656,
        Value50 = 562949953421312,
        Value51 = 1125899906842624,
        Value52 = 2251799813685248,
        Value53 = 4503599627370496,
        Value54 = 9007199254740992,
        Value55 = 18014398509481984,
        Value56 = 36028797018963968,
        Value57 = 72057594037927936,
        Value58 = 144115188075855872,
        Value59 = 288230376151711744,
        Value60 = 576460752303423488,
        Value61 = 1152921504606846976,
        Value62 = 2305843009213693952,
        Value63 = 4611686018427387904,
        Value64 = 9223372036854775808
    }
}
