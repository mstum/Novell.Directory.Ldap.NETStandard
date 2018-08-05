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
// Novell.Directory.Ldap.SupportClass.cs
//
// Author:
//   Sunil Kumar (Sunilk@novell.com)
//
// (C) 2003 Novell, Inc (http://www.novell.com)
//

// Support classes replicate the functionality of the original code, but in some cases they are
// substantially different architecturally. Although every effort is made to preserve the
// original architecture of the application in the converted project, the user should be aware that
// the primary goal of these support classes is to replicate functionality, and that at times
// the architecture of the resulting solution may differ somewhat.
//

using System;
using System.Collections;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading;

namespace Novell.Directory.Ldap
{
    /// <summary>
    ///     This interface should be implemented by any class whose instances are intended
    ///     to be executed by a thread.
    /// </summary>
    public interface IThreadRunnable
    {
        /// <summary>
        ///     This method has to be implemented in order that starting of the thread causes the object's
        ///     run method to be called in that separately executing thread.
        /// </summary>
        void Run();
    }

    public class Integer32 : object
    {
        public Integer32(int ival)
        {
            IntValue = ival;
        }

        public int IntValue { get; set; }
    }

    /// <summary>
    ///     Contains conversion support elements such as classes, interfaces and static methods.
    /// </summary>
    public class SupportClass
    {       
        /*******************************/

        /// <summary>
        ///     Reads a number of characters from the current source Stream and writes the data to the target array at the
        ///     specified index.
        /// </summary>
        /// <param name="sourceStream">The source Stream to read from.</param>
        /// <param name="target">Contains the array of characteres read from the source Stream.</param>
        /// <param name="start">The starting index of the target array.</param>
        /// <param name="count">The maximum number of characters to read from the source Stream.</param>
        /// <returns>
        ///     The number of characters read. The number will be less than or equal to count depending on the data available
        ///     in the source Stream. Returns -1 if the end of the stream is reached.
        /// </returns>
        [CLSCompliant(false)]
        public static int ReadInput(Stream sourceStream, ref byte[] target, int start, int count)
        {
            // Returns 0 bytes if not enough space in target
            if (target.Length == 0)
            {
                return 0;
            }

            var receiver = new byte[target.Length];
            var bytesRead = 0;
            var startIndex = start;
            var bytesToRead = count;
            while (bytesToRead > 0)
            {
                var n = sourceStream.Read(receiver, startIndex, bytesToRead);
                if (n == 0)
                {
                    break;
                }

                bytesRead += n;
                startIndex += n;
                bytesToRead -= n;
            }

            // Returns -1 if EOF
            if (bytesRead == 0)
            {
                return -1;
            }

            for (var i = start; i < start + bytesRead; i++)
            {
                target[i] = (byte)receiver[i];
            }

            return bytesRead;
        }
        
        /// <summary>
        ///     This method returns the literal value received.
        /// </summary>
        /// <param name="literal">The literal to return.</param>
        /// <returns>The received value.</returns>
        public static long Identity(long literal)
        {
            return literal;
        }

        /// <summary>
        ///     Adds a new key-and-value pair into the hash table.
        /// </summary>
        /// <param name="collection">The collection to work with.</param>
        /// <param name="key">Key used to obtain the value.</param>
        /// <param name="newValue">Value asociated with the key.</param>
        /// <returns>The old element associated with the key.</returns>
        public static object PutElement(IDictionary collection, object key, object newValue)
        {
            var element = collection[key];
            collection[key] = newValue;
            return element;
        }

        /*******************************/

        /// <summary>
        ///     Removes the first occurrence of an specific object from an ArrayList instance.
        /// </summary>
        /// <param name="arrayList">The ArrayList instance.</param>
        /// <param name="element">The element to remove.</param>
        /// <returns>True if item is found in the ArrayList; otherwise, false.</returns>
        public static bool VectorRemoveElement(ArrayList arrayList, object element)
        {
            var containsItem = arrayList.Contains(element);
            arrayList.Remove(element);
            return containsItem;
        }

        /*******************************/

        /// <summary>
        ///     Removes the element with the specified key from a Hashtable instance.
        /// </summary>
        /// <param name="hashtable">The Hashtable instance.</param>
        /// <param name="key">The key of the element to remove.</param>
        /// <returns>The element removed.</returns>
        public static object HashtableRemove(Hashtable hashtable, object key)
        {
            var element = hashtable[key];
            hashtable.Remove(key);
            return element;
        }

        /*******************************/

        /// <summary>
        ///     Sets the size of the ArrayList. If the new size is greater than the current capacity, then new null items are added
        ///     to the end of the ArrayList. If the new size is lower than the current size, then all elements after the new size
        ///     are discarded.
        /// </summary>
        /// <param name="arrayList">The ArrayList to be changed.</param>
        /// <param name="newSize">The new ArrayList size.</param>
        public static void SetSize(ArrayList arrayList, int newSize)
        {
            if (newSize < 0)
            {
                throw new ArgumentException();
            }

            if (newSize < arrayList.Count)
            {
                arrayList.RemoveRange(newSize, arrayList.Count - newSize);
            }
            else
            {
                while (newSize > arrayList.Count)
                {
                    arrayList.Add(null);
                }
            }
        }

        /// <summary>
        ///     Adds an element to the top end of a Stack instance.
        /// </summary>
        /// <param name="stack">The Stack instance.</param>
        /// <param name="element">The element to add.</param>
        /// <returns>The element added.</returns>
        public static object StackPush(Stack stack, object element)
        {
            stack.Push(element);
            return element;
        }

        /// <summary>
        ///     Copies an array of chars obtained from a String into a specified array of chars.
        /// </summary>
        /// <param name="sourceString">The String to get the chars from.</param>
        /// <param name="sourceStart">Position of the String to start getting the chars.</param>
        /// <param name="sourceEnd">Position of the String to end getting the chars.</param>
        /// <param name="destinationArray">Array to return the chars.</param>
        /// <param name="destinationStart">Position of the destination array of chars to start storing the chars.</param>
        /// <returns>An array of chars.</returns>
        public static void GetCharsFromString(string sourceString, int sourceStart, int sourceEnd,
            ref char[] destinationArray, int destinationStart)
        {
            var sourceCounter = sourceStart;
            var destinationCounter = destinationStart;
            while (sourceCounter < sourceEnd)
            {
                destinationArray[destinationCounter] = sourceString[sourceCounter];
                sourceCounter++;
                destinationCounter++;
            }
        }

        /// <summary>
        ///     Determines whether two Collections instances are equals.
        /// </summary>
        /// <param name="source">The first Collections to compare. </param>
        /// <param name="target">The second Collections to compare. </param>
        /// <returns>Return true if the first collection is the same instance as the second collection, otherwise return false.</returns>
        public static bool EqualsSupport(ICollection source, ICollection target)
        {
            var sourceEnumerator = ReverseStack(source);
            var targetEnumerator = ReverseStack(target);

            if (source.Count != target.Count)
            {
                return false;
            }

            while (sourceEnumerator.MoveNext() && targetEnumerator.MoveNext())
            {
                if (!sourceEnumerator.Current.Equals(targetEnumerator.Current))
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        ///     Reverses the Stack Collection received.
        /// </summary>
        /// <param name="collection">The collection to reverse.</param>
        /// <returns>
        ///     The collection received in reverse order if it was a System.Collections.Stack type, otherwise it does
        ///     nothing to the collection.
        /// </returns>
        public static IEnumerator ReverseStack(ICollection collection)
        {
            if (collection.GetType() == typeof(Stack))
            {
                var collectionStack = new ArrayList(collection);
                collectionStack.Reverse();
                return collectionStack.GetEnumerator();
            }

            return collection.GetEnumerator();
        }

        /*******************************/

        /// <summary>
        ///     The class performs token processing from strings.
        /// </summary>
        public class Tokenizer
        {
            private readonly bool _returnDelims;

            // The tokenizer uses the default delimiter set: the space character, the tab character, the newline character, and the carriage-return character
            private string _delimiters = " \t\n\r";

            // Element list identified
            private ArrayList _elements;

            // Source string to use
            private string _source;

            /// <summary>
            ///     Initializes a new class instance with a specified string to process
            ///     and the specified token delimiters to use.
            /// </summary>
            /// <param name="source">String to tokenize.</param>
            /// <param name="delimiters">String containing the delimiters.</param>
            public Tokenizer(string source, string delimiters)
            {
                _elements = new ArrayList();
                _delimiters = delimiters;
                _elements.AddRange(source.Split(_delimiters.ToCharArray()));
                RemoveEmptyStrings();
                _source = source;
            }

            public Tokenizer(string source, string delimiters, bool retDel)
            {
                _elements = new ArrayList();
                _delimiters = delimiters;
                _source = source;
                _returnDelims = retDel;
                if (_returnDelims)
                {
                    Tokenize();
                }
                else
                {
                    _elements.AddRange(source.Split(_delimiters.ToCharArray()));
                }

                RemoveEmptyStrings();
            }

            /// <summary>
            ///     Current token count for the source string.
            /// </summary>
            public int Count => _elements.Count;

            private void Tokenize()
            {
                var tempstr = _source;
                var toks = string.Empty;
                if (tempstr.IndexOfAny(_delimiters.ToCharArray()) < 0 && tempstr.Length > 0)
                {
                    _elements.Add(tempstr);
                }
                else if (tempstr.IndexOfAny(_delimiters.ToCharArray()) < 0 && tempstr.Length <= 0)
                {
                    return;
                }

                while (tempstr.IndexOfAny(_delimiters.ToCharArray()) >= 0)
                {
                    if (tempstr.IndexOfAny(_delimiters.ToCharArray()) == 0)
                    {
                        if (tempstr.Length > 1)
                        {
                            _elements.Add(tempstr.Substring(0, 1));
                            tempstr = tempstr.Substring(1);
                        }
                        else
                        {
                            tempstr = string.Empty;
                        }
                    }
                    else
                    {
                        toks = tempstr.Substring(0, tempstr.IndexOfAny(_delimiters.ToCharArray()));
                        _elements.Add(toks);
                        _elements.Add(tempstr.Substring(toks.Length, 1));
                        if (tempstr.Length > toks.Length + 1)
                        {
                            tempstr = tempstr.Substring(toks.Length + 1);
                        }
                        else
                        {
                            tempstr = string.Empty;
                        }
                    }
                }

                if (tempstr.Length > 0)
                {
                    _elements.Add(tempstr);
                }
            }

            /// <summary>
            ///     Determines if there are more tokens to return from the source string.
            /// </summary>
            /// <returns>True or false, depending if there are more tokens.</returns>
            public bool HasMoreTokens()
            {
                return _elements.Count > 0;
            }

            /// <summary>
            ///     Returns the next token from the token list.
            /// </summary>
            /// <returns>The string value of the token.</returns>
            public string NextToken()
            {
                string result;
                if (_source == string.Empty)
                {
                    throw new Exception();
                }

                if (_returnDelims)
                {
// Tokenize();
                    RemoveEmptyStrings();
                    result = (string)_elements[0];
                    _elements.RemoveAt(0);
                    return result;
                }

                _elements = new ArrayList();
                _elements.AddRange(_source.Split(_delimiters.ToCharArray()));
                RemoveEmptyStrings();
                result = (string)_elements[0];
                _elements.RemoveAt(0);
                _source = _source.Remove(_source.IndexOf(result), result.Length);
                _source = _source.TrimStart(_delimiters.ToCharArray());
                return result;
            }

            /// <summary>
            ///     Removes all empty strings from the token list.
            /// </summary>
            private void RemoveEmptyStrings()
            {
                for (var index = 0; index < _elements.Count; index++)
                {
                    if ((string)_elements[index] == string.Empty)
                    {
                        _elements.RemoveAt(index);
                        index--;
                    }
                }
            }
        }

        /// <summary>
        ///     This class contains static methods to manage arrays.
        /// </summary>
        public static class ArrayListSupport
        {
            /// <summary>
            ///     Obtains an array containing all the elements of the collection.
            /// </summary>
            /// <param name="collection">The collection from wich to obtain the elements.</param>
            /// <param name="objects">The array containing all the elements of the collection.</param>
            /// <returns>The array containing all the elements of the collection.</returns>
            public static object[] ToArray(ArrayList collection, object[] objects)
            {
                var index = 0;
                var tempEnumerator = collection.GetEnumerator();
                while (tempEnumerator.MoveNext())
                {
                    objects[index++] = tempEnumerator.Current;
                }

                return objects;
            }
        }

        /*******************************/

        /// <summary>
        ///     Support class used to handle threads.
        /// </summary>
        public class ThreadClass : IThreadRunnable
        {
            /// <summary>
            ///     The instance of System.Threading.Thread.
            /// </summary>
            private Thread _threadField;

            /// <summary>
            ///     Initializes a new instance of the ThreadClass class.
            /// </summary>
            protected ThreadClass()
            {
                _threadField = new Thread(Run);
            }
            
            /// <summary>
            ///     Gets the current thread instance.
            /// </summary>
            private Thread Instance
            {
                get => _threadField;
                set => _threadField = value;
            }

            /// <summary>
            ///     Gets or sets the name of the thread.
            /// </summary>
            private string Name
            {
                get => _threadField.Name;
                set
                {
                    if (_threadField.Name == null)
                    {
                        _threadField.Name = value;
                    }
                }
            }

            /// <summary>
            ///     Gets or sets a value indicating whether or not a thread is a background thread.
            /// </summary>
            public bool IsBackground
            {
                get => _threadField.IsBackground;
                set => _threadField.IsBackground = value;
            }

            protected bool IsStopping { get; private set; }

            /// <summary>
            ///     This method has no functionality unless the method is overridden.
            /// </summary>
            public virtual void Run()
            {
            }

            /// <summary>
            ///     Causes the operating system to change the state of the current thread instance to ThreadState.Running.
            /// </summary>
            public void Start()
            {
                _threadField.Start();
            }

            public void Stop()
            {
                IsStopping = true;
            }

            /// <summary>
            ///     Obtain a String that represents the current Object.
            /// </summary>
            /// <returns>A String that represents the current Object.</returns>
            public override string ToString()
            {
                return "Thread[" + Name + "]";
            }
        }

        
        /// <summary>
        ///     This class manages a set of elements.
        /// </summary>
        public class SetSupport : ArrayList
        {
            /// <summary>
            ///     Creates a new set.
            /// </summary>
            public SetSupport()
            {
            }

            /// <summary>
            ///     Creates a new set initialized with System.Collections.ICollection object.
            /// </summary>
            /// <param name="collection">System.Collections.ICollection object to initialize the set object.</param>
            public SetSupport(ICollection collection)
                : base(collection)
            {
            }

            /// <summary>
            ///     Adds an element to the set.
            /// </summary>
            /// <param name="objectToAdd">The object to be added.</param>
            /// <returns>True if the object was added, false otherwise.</returns>
            public new virtual bool Add(object objectToAdd)
            {
                if (Contains(objectToAdd))
                {
                    return false;
                }

                base.Add(objectToAdd);
                return true;
            }

            /// <summary>
            ///     Verifies if the collection is empty.
            /// </summary>
            /// <returns>True if the collection is empty, false otherwise.</returns>
            public virtual bool IsEmpty()
            {
                return Count == 0;
            }

            /// <summary>
            ///     Removes an element from the set.
            /// </summary>
            /// <param name="elementToRemove">The element to be removed.</param>
            /// <returns>True if the element was removed.</returns>
            public new virtual bool Remove(object elementToRemove)
            {
                var result = false;
                if (Contains(elementToRemove))
                {
                    result = true;
                }

                base.Remove(elementToRemove);
                return result;
            }
        }

        /// <summary>
        ///     This class manages different operation with collections.
        /// </summary>
        public class AbstractSetSupport : SetSupport
        {
        }
    }
}