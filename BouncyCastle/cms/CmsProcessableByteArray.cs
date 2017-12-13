
using System;
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Cms
{
    public class CmsProcessableByteArray : ICmsTypedData, CmsReadable
    {
        private readonly DerObjectIdentifier type;
        private readonly byte[] bytes;

        public CmsProcessableByteArray(byte[] bytes):  this(CmsObjectIdentifiers.Data, bytes)
        {
           
        }

        public CmsProcessableByteArray(
            DerObjectIdentifier type,
            byte[] bytes)
        {
            this.type = type;
            this.bytes = bytes;
        }

        public DerObjectIdentifier ContentType
        {
            get
            {
                return type;
            }
        }

        public object GetContent()
        {
            return Arrays.Clone(bytes);
        }

        public void Write(Stream output)
        {
            output.Write(bytes, 0, bytes.Length);
        }

        public Stream GetInputStream()
        {
            return new MemoryInputStream(bytes);
        }
    }
}
