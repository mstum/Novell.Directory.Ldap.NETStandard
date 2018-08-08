using Novell.Directory.Ldap.Asn1;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Novell.Directory.Ldap.Asn1
{
    /// <summary>
    /// GeneralizedTime [UNIVERSAL 24]
    /// </summary>
    public class Asn1GeneralizedTime : Asn1VisibleString
    {
        public new const int Tag = 24;
        public new static readonly Asn1Identifier Id = new Asn1Identifier(Asn1Identifier.Universal, true, Tag);

        public Asn1GeneralizedTime() : base(Id)
        {
        }

        protected Asn1GeneralizedTime(Asn1Identifier id) : base(id)
        {
        }
    }
}
