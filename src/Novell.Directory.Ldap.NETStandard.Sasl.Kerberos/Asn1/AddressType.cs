namespace Novell.Directory.Ldap.Sasl.Kerberos
{
    /// <summary>
    /// All negative values for the host address type are reserved for local
    /// use. All non-negative values are reserved for officially assigned
    /// type fields and interpretations.
    /// </summary>
    public enum AddressType : int
    {
        IPv4 = 2,
        Diretional = 3,
        ChaosNet = 5,
        XNS = 6,
        ISO = 7,
        DECNETPhaseIV = 12,
        AppleTalkDDP = 16,
        NetBios = 20,
        IPv6 = 24
    }
}
