
using System.IO;
using Org.BouncyCastle.Crypto.Internal;

namespace Org.BouncyCastle.Crypto
{
	internal class CipherImpl: ICipher
	{
		private readonly IBufferedCipher cipher;
		private readonly Stream source;

		internal CipherImpl(IBufferedCipher cipher, Stream source)
		{
			this.cipher = cipher;
			this.source = source;
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

