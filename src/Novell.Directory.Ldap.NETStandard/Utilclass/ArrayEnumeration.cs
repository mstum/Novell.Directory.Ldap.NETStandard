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
// Novell.Directory.Ldap.Utilclass.ArrayEnumeration.cs
//
// Author:
//   Sunil Kumar (Sunilk@novell.com)
//
// (C) 2003 Novell, Inc (http://www.novell.com)
//

using System;
using System.Collections;

namespace Novell.Directory.Ldap.Utilclass
{
    public sealed class ArrayEnumeration : IEnumerator
    {
        private object _tempAuxObj;

        public bool MoveNext()
        {
            var result = HasMoreElements();
            if (result)
            {
                _tempAuxObj = NextElement();
            }
            return result;
        }

        public void Reset()
        {
            _tempAuxObj = null;
        }

        public object Current => _tempAuxObj;

        private readonly object[] _eArray;
        private int _index;

        /// <summary>
        ///     Constructor to create the Enumeration
        /// </summary>
        /// <param name="eArray">
        ///     the array to use for the Enumeration
        /// </param>
        public ArrayEnumeration(object[] eArray)
        {
            _eArray = eArray;
        }

        public bool HasMoreElements()
        {
            if (_eArray == null)
                return false;
            return _index < _eArray.Length;
        }

        public object NextElement()
        {
            if (_eArray == null || _index >= _eArray.Length)
            {
                throw new ArgumentOutOfRangeException();
            }
            return _eArray[_index++];
        }
    }
}