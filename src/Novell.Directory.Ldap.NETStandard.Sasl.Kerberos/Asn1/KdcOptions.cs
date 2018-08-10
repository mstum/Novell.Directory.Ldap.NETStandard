using System;
using System.Collections.Generic;
using System.Text;

namespace Novell.Directory.Ldap.Sasl.Asn1
{
    /// <summary>
    /// KDCOptions      ::= KerberosFlags
    ///         -- reserved(0),
    ///         -- forwardable(1),
    ///         -- forwarded(2),
    ///         -- proxiable(3),
    ///         -- proxy(4),
    ///         -- allow-postdate(5),
    ///         -- postdated(6),
    ///         -- unused7(7),
    ///         -- renewable(8),
    ///         -- unused9(9),
    ///         -- unused10(10),
    ///         -- opt-hardware-auth(11),
    ///         -- unused12(12),
    ///         -- unused13(13),
    /// -- 15 is reserved for canonicalize
    ///         -- unused15(15),
    /// -- 26 was unused in 1510
    ///         -- disable-transited-check(26),
    /// --
    ///         -- renewable-ok(27),
    ///         -- enc-tkt-in-skey(28),
    ///         -- renew(30),
    ///         -- validate(31)
    /// </summary>
    /// <remarks>
    /// The first bit in a bit string is called the leading bit. The final bit in a bit string is called the trailing bit.
    /// The leading bit of the bit string is identified by the "number" zero, with succeeding bits having successive values.
    /// 
    /// So forwardable(1) would be:
    /// 0b01000000_00000000_00000000_00000000
    /// = 1073741824 dec.
    /// This is equivalent to <code>1 &lt;&lt; 30</code>.
    /// Or, in this case, 31-1.
    /// </remarks>
    [Flags]
    public enum KdcOptions : uint // KerberosFlags   ::= BIT STRING (SIZE (32..MAX))
    {
        Reserved = 1u << 31,
        Forwardable = 1 << (31-1),
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
}
