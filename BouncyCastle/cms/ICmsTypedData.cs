using Org.BouncyCastle.Asn1;
using System.IO;

namespace Org.BouncyCastle.Cms
{
    public interface ICmsTypedData
    {
        DerObjectIdentifier ContentType { get; }

        object GetContent();

        /// <summary>
        /// generic routine to copy out the data we want processed - the OutputStream
        /// passed in will do the handling on it's own.
        /// Note: this routine may be called multiple times.
        /// </summary>
        /// <param name="output"></param>
        void Write(Stream output);
    }
}
