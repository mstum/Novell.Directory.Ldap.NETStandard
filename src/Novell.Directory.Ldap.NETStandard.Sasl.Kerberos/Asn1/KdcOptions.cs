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
    [Flags]
    public enum KdcOptions : uint // KerberosFlags   ::= BIT STRING (SIZE (32..MAX))
    {
        Reserved = 1u << 0,
        Forwardable = 1u << 1,
        Forwarded = 1u << 2,
        Proxiable = 1u << 3,
        Proxy = 1u << 4,
        AllowPostDate = 1u << 5,
        PostDated = 1u << 6,
        Unused7 = 1u << 7,

        Renewable = 1u << 8,
        Unused9 = 1u << 9,
        Unused10 = 1u << 10,
        OptHardwareAuth = 1u << 11,
        Unused12 = 1u << 12,
        Unused13 = 1u << 13,
        ConstrainedDelegation = 1u << 14,
        Canonicalize = 1u << 15, // added in RFC 6806

        RequestAnonymous = 1u << 16, // added in RFC 6112 / 8062
        Unused17 = 1u << 17,
        Unused18 = 1u << 18,
        Unused19 = 1u << 19,
        Unused20 = 1u << 20,
        Unused21 = 1u << 21,
        Unused22 = 1u << 22,

        Unused23 = 1u << 23,
        Unused24 = 1u << 24,
        Unused25 = 1u << 25,
        DisableTransitedCheck = 1u << 26, // added in RFC 4120
        RenewableOk = 1u << 27,
        EncTicketInSKey = 1u << 28,
        Unused29 = 1u << 29,
        Renew = 1u << 30,
        Validate = 1u << 31
    }
}
