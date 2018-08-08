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
// Novell.Directory.Ldap.Extensions.ListReplicasResponse.cs
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
    ///     Retrieves the list of replicas from the specified server.
    ///     An object in this class is generated from an ExtendedResponse object
    ///     using the ExtendedResponseFactory class.
    ///     The listReplicaResponse extension uses the following OID:
    ///     2.16.840.1.113719.1.27.20.
    /// </summary>
    public class ListReplicasResponse : LdapExtendedResponse
    {
        // Identity returned by the server

        /// <summary>
        ///     Constructs an object from the responseValue which contains the list
        ///     of replicas.
        ///     The constructor parses the responseValue which has the following
        ///     format:
        ///     responseValue ::=
        ///     replicaList
        ///     SEQUENCE OF OCTET STRINGS.
        /// </summary>
        /// <exception>
        ///     IOException  The responseValue could not be decoded.
        /// </exception>
        public ListReplicasResponse(RfcLdapMessage rfcMessage)
            : base(rfcMessage)
        {
            if (ResultCode != LdapException.Success)
            {
                ReplicaList = new string[0];
            }
            else
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

                // We should get back a sequence
                var returnedSequence = (Asn1Sequence)decoder.Decode(returnedValue, null);
                if (returnedSequence == null)
                {
                    throw new IOException("Decoding error");
                }

                // How many replicas were returned
                var len = returnedSequence.Size();
                ReplicaList = new string[len];

                // Copy each one into our String array
                for (var i = 0; i < len; i++)
                {
                    // Get the next Asn1Octet String in the sequence
                    var asn1NextReplica = (Asn1OctetString)returnedSequence.get_Renamed(i);
                    if (asn1NextReplica == null)
                    {
                        throw new IOException("Decoding error");
                    }

                    // Convert to a string
                    ReplicaList[i] = asn1NextReplica.StringValue();
                    if ((object)ReplicaList[i] == null)
                    {
                        throw new IOException("Decoding error");
                    }
                }
            }
        }

        /// <summary>
        ///     Returns a list of distinguished names for the replicas on the server.
        /// </summary>
        /// <returns>
        ///     String value specifying the identity returned by the server.
        /// </returns>
        public string[] ReplicaList { get; }
    }
}