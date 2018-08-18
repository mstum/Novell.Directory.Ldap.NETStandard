using System;

namespace Novell.Directory.Ldap.Sasl.Kerberos
{
    /// <summary>
    /// TicketFlags     ::= KerberosFlags
    ///         -- reserved(0),
    ///         -- forwardable(1),
    ///         -- forwarded(2),
    ///         -- proxiable(3),
    ///         -- proxy(4),
    ///         -- may-postdate(5),
    ///         -- postdated(6),
    ///         -- invalid(7),
    ///         -- renewable(8),
    ///         -- initial(9),
    ///         -- pre-authent(10),
    ///         -- hw-authent(11),
    /// -- the following are new since 1510
    ///         -- transited-policy-checked(12),
    ///         -- ok-as-delegate(13)
    ///         -- anonymous(16)
    /// </summary>
    [Flags]
    public enum TicketFlags : uint
    {
        Reserved = 1u << 0,
        Forwardable = 1u << 1,
        Forwarded = 1u << 2,
        Proxiable = 1u << 3,
        Proxy = 1u << 4,
        MayPostDate = 1u << 5,
        Postdated = 1u << 6,
        Invalid = 1u << 7,
        Renewable = 1u << 8,
        Initial = 1u << 9,
        PreAuthent = 1u << 10,
        HwAuthent = 1u << 11,
        TransitedPolicyChecked = 1u << 12,
        OkAsDelegate = 1u << 13,
        Anonymous = 1u << 16 // RFC 6112
    }
}
