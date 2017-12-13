using System;
using System.IO;

namespace Org.BouncyCastle.Crypto
{
	using Org.BouncyCastle.Crypto.Internal;

	internal class VerifierCalculator : IStreamCalculator<IVerifier>
	{
		private readonly ISigner sig;
		private readonly Stream stream;

		internal VerifierCalculator(ISigner sig)
		{
			this.sig = sig;
			this.stream = new SignatureBucket(sig);
		}

		public Stream Stream
		{
			get { return stream; }
		}

		public IVerifier GetResult()
		{
			return new VerifierResult (sig);
		}

		private class VerifierResult: IVerifier
		{
			private readonly ISigner sig;

			internal VerifierResult(ISigner sig)
			{
				this.sig = sig;
			}

			public bool IsVerified(byte[] data)
			{
                try
                {
                    return sig.VerifySignature(data);
                }
                catch (Exception)
                {
                    return false;
                }
			}

			public bool IsVerified(byte[] source, int off, int length)
			{
				byte[] s = new byte[length];

				Array.Copy (source, off, s, 0, length);

				return IsVerified (s);
			}
		}
	}
}

