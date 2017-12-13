using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
	public abstract class SignatureParameters<TParam, TAlg, DAlg>
        : Parameters<TAlg>, ISignatureParameters<TParam, TAlg, DAlg>
        where TParam : IParameters<TAlg>
        where TAlg : Algorithm
        where DAlg : DigestAlgorithm
	{
		private readonly DAlg digestAlgorithm;

		internal SignatureParameters(TAlg algorithm, DAlg digestAlgorithm): base(algorithm)
		{
			this.digestAlgorithm = digestAlgorithm;
		}

		public DAlg DigestAlgorithm
		{
			get { return digestAlgorithm; }
		}

		public TParam WithDigest(DAlg digestAlgorithm)
		{
			return CreateParameter(Algorithm, digestAlgorithm);
		}

		internal abstract TParam CreateParameter(TAlg algorithm, DAlg digestAlgorithm);
	}
}
