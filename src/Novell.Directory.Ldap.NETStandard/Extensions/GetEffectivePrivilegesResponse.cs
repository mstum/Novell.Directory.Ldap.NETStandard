/******************************************************************************
* The MIT License
* Copyright (c) 2003 Novell Inc.  www.novell.com
*
* Permission is hereby granted, free of charge, to any person obtaining  a copy
* of this software and associated documentation files (the Software), to deal
* in the Software without restriction, including  without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to  permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*******************************************************************************/

//
// Novell.Directory.Ldap.Extensions.GetEffectivePrivilegesResponse.cs
//
// Author:
//   Sunil Kumar (Sunilk@novell.com)
//
// (C) 2003 Novell, Inc (http://www.novell.com)
//

using System.IO;
using Novell.Directory.Ldap.Asn1;
using Novell.Directory.Ldap.Rfc2251;

namespace Novell.Directory.Ldap.Extensions
{
    /// <summary>
    ///     Retrieves the effective rights from an GetEffectivePrivilegesResponse object.
    ///     An object in this class is generated from an ExtendedResponse object
    ///     using the ExtendedResponseFactory class.
    ///     The getEffectivePrivilegesResponse extension uses the following OID:
    ///     2.16.840.1.113719.1.27.100.34.
    /// </summary>
    public class GetEffectivePrivilegesResponse : LdapExtendedResponse
    {
        // Identity returned by the server

        /// <summary>
        ///     Constructs an object from the responseValue which contains the effective
        ///     privileges.
        ///     The constructor parses the responseValue which has the following
        ///     format:
        ///     responseValue ::=
        ///     privileges  INTEGER.
        /// </summary>
        /// <exception>
        ///     IOException The responseValue could not be decoded.
        /// </exception>
        public GetEffectivePrivilegesResponse(RfcLdapMessage rfcMessage)
            : base(rfcMessage)
        {
            if (ResultCode == LdapException.Success)
            {
                // parse the contents of the reply
                var returnedValue = Value;
                if (returnedValue == null)
                {
                    throw new IOException("No returned value");
                }

                // Create a decoder object
                var decoder = new LberDecoder();
                if (decoder == null)
                {
                    throw new IOException("Decoding error");
                }

                var asn1Privileges = (Asn1Integer)decoder.Decode(returnedValue);
                if (asn1Privileges == null)
                {
                    throw new IOException("Decoding error");
                }

                Privileges = asn1Privileges.IntValue();
            }
            else
            {
                Privileges = 0;
            }
        }

        /// <summary>
        ///     Returns the effective privileges.
        ///     See the ReplicationConstants class for the privilege flags.
        /// </summary>
        /// <returns>
        ///     A flag which is a combination of zero or more privilege flags as
        ///     returned by the server.
        /// </returns>
        public int Privileges { get; }
    }
}