using System;
using System.IO;

namespace Org.BouncyCastle.Crypto
{
	using Org.BouncyCastle.Crypto.Internal;

	internal class SignatureCalculator : IStreamCalculator<IBlockResult>
	{
		private readonly ISigner sig;
		private readonly Stream stream;

		internal SignatureCalculator(ISigner sig)
		{
			this.sig = sig;
			this.stream = new SignatureBucket(sig);
		}

		public Stream Stream
		{
			get { return stream; }
		}

		public IBlockResult GetResult()
		{
			return new SignatureResult(sig);
		}
	}
}

