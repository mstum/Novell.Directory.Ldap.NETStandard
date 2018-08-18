namespace Novell.Directory.Ldap.Sasl.Kerberos
{
    /// <summary>
    /// APOptions       ::= KerberosFlags
    ///         -- reserved(0),
    ///         -- use-session-key(1),
    ///         -- mutual-required(2)
    /// </summary>
    public enum ApOptions : uint
    {
        Reserved = 1u << 0,
        UseSessionKey = 1u << 1,
        MutualRequired = 1u << 2
    }
}
