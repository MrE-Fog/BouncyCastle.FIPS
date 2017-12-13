using System;
using System.Globalization;
using System.IO;
using System.Text;

#if SILVERLIGHT || PORTABLE
using System.Collections.Generic;
#else
using System.Collections;
#endif

namespace Org.BouncyCastle.Utilities
{
    public abstract class Platform
    {
        private static readonly CompareInfo InvariantCompareInfo = CultureInfo.InvariantCulture.CompareInfo;

#if NETCF_1_0 || NETCF_2_0
        private static string GetNewLine()
        {
            MemoryStream buf = new MemoryStream();
            StreamWriter w = new StreamWriter(buf, Encoding.UTF8);
            w.WriteLine();
            Dispose(w);
            byte[] bs = buf.ToArray();
            return Encoding.UTF8.GetString(bs, 0, bs.Length);
        }
#else
        private static string GetNewLine()
        {
            return Environment.NewLine;
        }
#endif

        internal static bool EqualsIgnoreCase(string a, string b)
        {
#if PORTABLE
            return String.Equals(a, b, StringComparison.OrdinalIgnoreCase);
#else
            return ToUpperInvariant(a) == ToUpperInvariant(b);
#endif
        }

#if NETCF_1_0 || NETCF_2_0 || SILVERLIGHT || PORTABLE
        internal static string GetEnvironmentVariable(
            string variable)
        {
            return null;
        }
#else
        internal static string GetEnvironmentVariable(
            string variable)
        {
            try
            {
                return Environment.GetEnvironmentVariable(variable);
            }
            catch (System.Security.SecurityException)
            {
                // We don't have the required permission to read this environment variable,
                // which is fine, just act as if it's not set
                return null;
            }
        }
#endif

#if NETCF_1_0
        internal static Exception CreateNotImplementedException(
            string message)
        {
            return new Exception("Not implemented: " + message);
        }

        internal static bool Equals(
            object	a,
            object	b)
        {
            return a == b || (a != null && b != null && a.Equals(b));
        }
#else
        public static Exception CreateNotImplementedException(
            string message)
        {
            return new NotImplementedException(message);
        }
#endif

#if SILVERLIGHT || PORTABLE
        internal static System.Collections.IList CreateArrayList()
        {
            return new List<object>();
        }
        internal static System.Collections.IList CreateArrayList(int capacity)
        {
            return new List<object>(capacity);
        }
        internal static System.Collections.IList CreateArrayList(System.Collections.ICollection collection)
        {
            System.Collections.IList result = new List<object>(collection.Count);
            foreach (object o in collection)
            {
                result.Add(o);
            }
            return result;
        }
        internal static System.Collections.IList CreateArrayList(System.Collections.IEnumerable collection)
        {
            System.Collections.IList result = new List<object>();
            foreach (object o in collection)
            {
                result.Add(o);
            }
            return result;
        }
        internal static System.Collections.IDictionary CreateHashtable()
        {
            return new Dictionary<object, object>();
        }
        internal static System.Collections.IDictionary CreateHashtable(int capacity)
        {
            return new Dictionary<object, object>(capacity);
        }
        internal static System.Collections.IDictionary CreateHashtable(System.Collections.IDictionary dictionary)
        {
            System.Collections.IDictionary result = new Dictionary<object, object>(dictionary.Count);
            foreach (System.Collections.DictionaryEntry entry in dictionary)
            {
                result.Add(entry.Key, entry.Value);
            }
            return result;
        }
#else
        public static System.Collections.IList CreateArrayList()
        {
            return new ArrayList();
        }

        public static System.Collections.IList CreateArrayList(int capacity)
        {
            return new ArrayList(capacity);
        }
        public static System.Collections.IList CreateArrayList(System.Collections.ICollection collection)
        {
            return new ArrayList(collection);
        }
        internal static System.Collections.IList CreateArrayList(System.Collections.IEnumerable collection)
        {
            ArrayList result = new ArrayList();
            foreach (object o in collection)
            {
                result.Add(o);
            }
            return result;
        }
        public static System.Collections.IDictionary CreateHashtable()
        {
            return new Hashtable();
        }
        internal static System.Collections.IDictionary CreateHashtable(int capacity)
        {
            return new Hashtable(capacity);
        }
        public static System.Collections.IDictionary CreateHashtable(System.Collections.IDictionary dictionary)
        {
            return new Hashtable(dictionary);
        }
#endif

        public static string ToLowerInvariant(string s)
        {
#if PORTABLE
            return s.ToLowerInvariant();
#else
            return s.ToLower(CultureInfo.InvariantCulture);
#endif
        }

        public static string ToUpperInvariant(string s)
        {
#if PORTABLE
            return s.ToUpperInvariant();
#else
            return s.ToUpper(CultureInfo.InvariantCulture);
#endif
        }

        public static readonly string NewLine = GetNewLine();

#if PORTABLE
        public static void Dispose(IDisposable d)
        {
            d.Dispose();
        }
#else
        public static void Dispose(Stream s)
        {
            s.Close();
        }

        public static void Dispose(TextWriter t)
        {
            t.Close();
        }
#endif

        internal static int IndexOf(string source, string value)
        {
            return InvariantCompareInfo.IndexOf(source, value, CompareOptions.Ordinal);
        }

        internal static int LastIndexOf(string source, string value)
        {
            return InvariantCompareInfo.LastIndexOf(source, value, CompareOptions.Ordinal);
        }

        internal static bool StartsWith(string source, string prefix)
        {
            return InvariantCompareInfo.IsPrefix(source, prefix, CompareOptions.Ordinal);
        }

        internal static bool EndsWith(string source, string suffix)
        {
            return InvariantCompareInfo.IsSuffix(source, suffix, CompareOptions.Ordinal);
        }

        internal static string GetTypeName(object obj)
        {
            return obj.GetType().FullName;
        }

        internal static string GetTypeName(Type t)
        {
            return t.FullName;
        }
    }
}
