
using Org.BouncyCastle.Crypto.Internal.Modes;
using System.IO;

namespace Org.BouncyCastle.Crypto
{
    internal class AeadCipherImpl: IAeadCipher
    {
        private readonly int macSize;
        private readonly IAeadBlockCipher cipher;
        private readonly Stream source;
        private readonly Stream aadStream;

        internal AeadCipherImpl(int macSize, IAeadBlockCipher cipher, Stream source)
        {
            this.macSize = macSize;
            this.cipher = cipher;
            this.source = source;
            this.aadStream = new AADBucket(cipher);
        }

        public int GetMaxOutputSize(int inputLen)
        {
            return cipher.GetOutputSize(inputLen);
        }

        public int GetUpdateOutputSize(int inputLen)
        {
            return cipher.GetUpdateOutputSize(inputLen);
        }

        public int MacSizeInBits
        {
            get
            {
                return macSize;
            }
        }

        public IBlockResult GetMac()
        {
            return new AeadResult((macSize + 7) / 8, cipher);
        }

        public Stream Stream { get { return source; } }

        public Stream AadStream
        {
            get
            {
                return aadStream;
            }
        }
    }
}
