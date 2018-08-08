namespace Novell.Directory.Ldap
{
    public static class LdapConnectionExtensionMethods
    {
        /// <summary>
        /// Register a SASL Handler for Kerberos
        /// </summary>
        /// <param name="conn"></param>
        public static void AddKerberosSupport(this LdapConnection conn)
        {
            var factory = new Sasl.KerberosSaslClientFactory();
            conn.RegisterSaslClientFactory(factory);
        }
    }
}
