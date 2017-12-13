
using System.IO;

using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.IO;

namespace Org.BouncyCastle.Crypto
{
	internal class CipherBuilderImpl<TParams>: ICipherBuilder<TParams> where TParams: IParameters<Algorithm>
	{
		private readonly IBufferedCipher cipher;
		private readonly TParams parameters;
		private readonly bool isApprovedModeOnly;

		internal CipherBuilderImpl(TParams parameters, IBufferedCipher cipher)
		{
			this.isApprovedModeOnly = CryptoServicesRegistrar.IsInApprovedOnlyMode ();
			this.parameters = parameters;
			this.cipher = cipher;
		}

		public TParams AlgorithmDetails { get { return parameters; } }

		public int BlockSize { get { return cipher.GetBlockSize(); } }

		public int GetMaxOutputSize (int inputLen)
		{
			return cipher.GetOutputSize (inputLen);
		}

		public ICipher BuildCipher(Stream stream)
		{
			CryptoServicesRegistrar.ApprovedModeCheck (isApprovedModeOnly, parameters.Algorithm.Name);

			return new CipherImpl (cipher, new CipherStream(stream, cipher));
		}
	}
}

