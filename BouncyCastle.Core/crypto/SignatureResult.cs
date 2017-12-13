using System;

namespace Org.BouncyCastle.Crypto
{
	using Org.BouncyCastle.Crypto.Internal;
	using Org.BouncyCastle.Crypto.Utilities;

	internal class SignatureResult : IBlockResult
	{
		private readonly byte[] sig;

		internal SignatureResult(ISigner sig)
		{
			this.sig = sig.GenerateSignature();
		}

		public int Length {
			get {
				return sig.Length;
			}
		}

		public byte[] Collect()
		{
			return sig;
		}

		public int Collect(byte[] destination, int offset)
		{
			Array.Copy (sig, 0, destination, offset, sig.Length);

			Array.Clear (sig, 0, sig.Length);

			return sig.Length;
		}
	}
}

