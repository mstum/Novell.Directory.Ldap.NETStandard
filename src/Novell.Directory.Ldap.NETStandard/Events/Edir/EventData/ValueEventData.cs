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
// Novell.Directory.Ldap.Events.Edir.EventData.ValueEventData.cs
//
// Author:
//   Anil Bhatia (banil@novell.com)
//
// (C) 2003 Novell, Inc (http://www.novell.com)
//

using System.Text;
using Novell.Directory.Ldap.Asn1;

namespace Novell.Directory.Ldap.Events.Edir.EventData
{
    /// <summary>
    ///     This class represents the data for Value Events.
    /// </summary>
    public class ValueEventData : BaseEdirEventData
    {
        protected byte[] BinData;

        protected int NVerb;
        protected string StrAttribute;

        protected string StrClassId;

        protected string StrData;

        protected string StrEntry;

        protected string StrPerpetratorDn;

        // syntax
        protected string StrSyntax;

        protected DseTimeStamp TimeStampObj;

        public ValueEventData(EdirEventDataType eventDataType, Asn1Object message)
            : base(eventDataType, message)
        {
            var length = new int[1];

            StrPerpetratorDn =
                ((Asn1OctetString)Decoder.Decode(DecodedData, length, null)).StringValue();
            StrEntry =
                ((Asn1OctetString)Decoder.Decode(DecodedData, length, null)).StringValue();
            StrAttribute =
                ((Asn1OctetString)Decoder.Decode(DecodedData, length, null)).StringValue();
            StrSyntax =
                ((Asn1OctetString)Decoder.Decode(DecodedData, length, null)).StringValue();

            StrClassId =
                ((Asn1OctetString)Decoder.Decode(DecodedData, length, null)).StringValue();

            TimeStampObj =
                new DseTimeStamp((Asn1Sequence)Decoder.Decode(DecodedData, length, null));

            var octData = (Asn1OctetString)Decoder.Decode(DecodedData, length, null);
            StrData = octData.StringValue();
            BinData = octData.ByteValue();

            NVerb = ((Asn1Integer)Decoder.Decode(DecodedData, length, null)).IntValue();

            DataInitDone();
        }

        public string Attribute => StrAttribute;

        public string ClassId => StrClassId;

        public string Data => StrData;

        public byte[] BinaryData => BinData;

        public string Entry => StrEntry;

        public string PerpetratorDn => StrPerpetratorDn;

        public string Syntax => StrSyntax;

        public DseTimeStamp TimeStamp => TimeStampObj;

        public int Verb => NVerb;

        /// <summary>
        ///     Returns a string representation of the object.
        /// </summary>
        public override string ToString()
        {
            var buf = new StringBuilder();

            buf.Append("[ValueEventData");
            buf.AppendFormat("(Attribute={0})", StrAttribute);
            buf.AppendFormat("(Classid={0})", StrClassId);
            buf.AppendFormat("(Data={0})", StrData);
            buf.AppendFormat("(Data={0})", BinData);
            buf.AppendFormat("(Entry={0})", StrEntry);
            buf.AppendFormat("(Perpetrator={0})", StrPerpetratorDn);
            buf.AppendFormat("(Syntax={0})", StrSyntax);
            buf.AppendFormat("(TimeStamp={0})", TimeStampObj);
            buf.AppendFormat("(Verb={0})", NVerb);
            buf.Append("]");

            return buf.ToString();
        }
    }
}