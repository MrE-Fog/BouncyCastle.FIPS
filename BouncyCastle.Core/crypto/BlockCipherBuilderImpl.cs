using System;
using System.IO;

using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.IO;

namespace Org.BouncyCastle.Crypto
{
	internal class BlockCipherBuilderImpl<TParams>: IBlockCipherBuilder<TParams> where TParams : IParameters<Algorithm>
    {
        private readonly bool isApprovedModeOnly;
		private readonly bool forEncryption;
		private readonly IBufferedCipher cipher;
		private readonly TParams parameters;

		internal BlockCipherBuilderImpl(bool forEncryption, TParams parameters, IBufferedCipher cipher)
		{
            this.isApprovedModeOnly = CryptoServicesRegistrar.IsInApprovedOnlyMode();
            this.forEncryption = forEncryption;
			this.parameters = parameters;
			this.cipher = cipher;
		}

		public TParams AlgorithmDetails { get { return parameters; } }

		public int BlockSize { get { return cipher.GetBlockSize(); } }

		public int GetMaxOutputSize (int inputLen)
		{
			int delta = inputLen % BlockSize;

			if (delta == 0) {
				if (forEncryption) {
					return inputLen + BlockSize;
				} else {
					return inputLen;
				}
			} else {
				if (forEncryption) {
					return inputLen + delta;
				} else {
					throw new ArgumentException ("decryption input for a block cipher must be block aligned");
				}
			}
		}

		public ICipher BuildPaddedCipher(Stream stream, IBlockCipherPadding padding)
		{
            CryptoServicesRegistrar.ApprovedModeCheck(isApprovedModeOnly, parameters.Algorithm.Name);

            if (forEncryption) {
				if (stream.CanWrite) {
					return new CipherImpl (cipher, new PaddingStream (forEncryption, padding, BlockSize, new CipherStream (stream, cipher)));
				} else {
					return new CipherImpl (cipher, new CipherStream(new PaddingStream (forEncryption, padding, BlockSize, stream), cipher));
				}
			} else {
				if (stream.CanWrite) {
					return new CipherImpl (cipher, new CipherStream (new PaddingStream (forEncryption, padding, BlockSize, stream), cipher));
				} else {
					return new CipherImpl (cipher, new PaddingStream (forEncryption, padding, BlockSize, new CipherStream (stream, cipher)));
				}
			}
		}

		public IBlockCipher BuildBlockCipher(Stream stream)
		{
            CryptoServicesRegistrar.ApprovedModeCheck(isApprovedModeOnly, parameters.Algorithm.Name);

            return new BlockCipherImpl(cipher, new CipherStream(stream, cipher));
		}
	}
}

