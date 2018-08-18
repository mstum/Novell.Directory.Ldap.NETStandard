using Novell.Directory.Ldap.Sasl;
using Novell.Directory.Ldap.Sasl.Kerberos;
using System.Collections;
using Xunit;

namespace Novell.Directory.Ldap.NETStandard.UnitTests
{
    public class KerberosSaslTests
    {
        private const string _gssApi = SaslConstants.Mechanism.GssApi;
        private LdapConnection GetConnection() => (LdapConnection)new LdapConnection().AddKerberosSupport();

        [Fact]
        public void LdapConnection_WithKerberosSupport_AddsGssApiHandler()
        {
            using (var conn = new LdapConnection())
            {
                Assert.False(conn.IsSaslMechanismSupported(_gssApi));
                conn.AddKerberosSupport();
                Assert.True(conn.IsSaslMechanismSupported(_gssApi));
            }
        }

        [Fact]
        public void LdapConnection_AddKerberosSupport_GssApi_CreatesClient()
        {
            using (var conn = GetConnection())
            {
                var client = conn.CreateClient(_gssApi, "unused", "unused", new byte[] { 0x00 }, new Hashtable());
                Assert.NotNull(client);
                Assert.IsType<KerberosSaslClient>(client);
            }
        }

        [Fact]
        public void RealLiveDebug()
        {
            using (var conn = GetConnection())
            {
                //conn.Connect("192.168.0.199", 389);
                //var kerbReq = new SaslKerberosRequest();
                //conn.Bind(kerbReq);
            }
        }
    }
}
