using System;
using Org.BouncyCastle.Crypto.Internal.Parameters;

namespace Org.BouncyCastle.Crypto.Internal.Generators
{
	/**
	 * Generator for Concatenation Key Derivation Function defined in NIST SP 800-56A, Sect 5.8.1
	 */
	internal class ConcatenationKdfGenerator: IDerivationFunction
	{
		private IDigest  digest;
		private byte[]  shared;
		private byte[]  otherInfo;
		private int     hLen;

		/**
	     * @param digest the digest to be used as the source of generated bytes
	     */
		public ConcatenationKdfGenerator(
			IDigest digest)
		{
			this.digest = digest;
			this.hLen = digest.GetDigestSize();
		}

		public void Init(
			IDerivationParameters    param)
		{
			if (param is KdfParameters)
			{
				KdfParameters p = (KdfParameters)param;

				shared = p.GetSharedSecret();
				otherInfo = p.GetIV();
			}
			else
			{
				throw new ArgumentException("KDF parameters required for KDF2Generator");
			}
		}

		/**
     * return the underlying digest.
     */
		public IDigest Digest
		{
			get {
				return digest;
			}
		}

		/**
     * int to octet string.
     */
		private void ItoOSP(
			uint     i,
			byte[]  sp)
		{
			sp[0] = (byte)(i >> 24);
			sp[1] = (byte)(i >> 16);
			sp[2] = (byte)(i >> 8);
			sp[3] = (byte)(i >> 0);
		}

		/**
     * fill len bytes of the output buffer with bytes generated from
     * the derivation function.
     *
     * @throws DataLengthException if the out buffer is too small.
     */
		public int GenerateBytes(
			byte[]  output,
			int     outOff,
			int     len)
		{
			if ((output.Length - len) < outOff)
			{
				throw new DataLengthException("output buffer too small");
			}

			byte[]  hashBuf = new byte[hLen];
			byte[]  C = new byte[4];
			uint    counter = 1;
			int     outputLen = 0;

			digest.Reset();

			if (len > hLen)
			{
				do
				{
					ItoOSP(counter, C);

					digest.BlockUpdate(C, 0, C.Length);
					digest.BlockUpdate(shared, 0, shared.Length);
					if (otherInfo != null)
					{
						digest.BlockUpdate(otherInfo, 0, otherInfo.Length);
					}

					digest.DoFinal(hashBuf, 0);

					Array.Copy(hashBuf, 0, output, outOff + outputLen, hLen);
					outputLen += hLen;
				}
				while ((counter++) < (len / hLen));
			}

			if (outputLen < len)
			{
				ItoOSP(counter, C);

				digest.BlockUpdate(C, 0, C.Length);
				digest.BlockUpdate(shared, 0, shared.Length);

				if (otherInfo != null)
				{
					digest.BlockUpdate(otherInfo, 0, otherInfo.Length);
				}

				digest.DoFinal(hashBuf, 0);

				Array.Copy(hashBuf, 0, output, outOff + outputLen, len - outputLen);
			}

			return len;
		}
	}

}

