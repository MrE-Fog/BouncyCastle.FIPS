
using System.IO;

namespace Org.BouncyCastle.Crypto
{
	internal class BlockCipherImpl: IBlockCipher
	{
		private readonly Org.BouncyCastle.Crypto.Internal.IBufferedCipher cipher;
		private readonly Stream source;

		internal BlockCipherImpl(Org.BouncyCastle.Crypto.Internal.IBufferedCipher cipher, Stream source)
		{
            this.cipher = cipher;
			this.source = source;
		}

		public int BlockSize { 
			get { return cipher.GetBlockSize(); }
		}

		public int GetMaxOutputSize (int inputLen)
		{
			return cipher.GetOutputSize (inputLen);
		}

		public int GetUpdateOutputSize(int inputLen)
		{
			return cipher.GetUpdateOutputSize (inputLen);
		}

		public Stream Stream { get { return source; } }
	}
}

