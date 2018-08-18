using Novell.Directory.Ldap.Asn1;
using Novell.Directory.Ldap.Sasl.Kerberos;

namespace Novell.Directory.Ldap
{
    public static class LdapConnectionExtensionMethods
    {
        /// <summary>
        /// Register a SASL Handler for Kerberos
        /// </summary>
        /// <param name="conn"></param>
        public static ILdapConnection AddKerberosSupport(this ILdapConnection conn)
        {
            var factory = new KerberosSaslClientFactory();
            conn.RegisterSaslClientFactory(factory);
            return conn;
        }

        public static IAsn1Decoder AddKerberosSupport(this IAsn1Decoder decoder)
        {
            decoder.AddDecoder(KerberosCodec.DecodeKerberosObject);
            return decoder;
        }
    }
}
