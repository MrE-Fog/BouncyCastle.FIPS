using Org.BouncyCastle.Crypto.Internal;

namespace Org.BouncyCastle.Crypto
{
	internal class DigestFactory<TParams>: IDigestFactory<TParams>
	{
        private readonly bool approvedOnlyMode;
		private readonly TParams parameters;
		private readonly int digestSize;
		private readonly IEngineProvider<IDigest> digestProvider;

		internal DigestFactory(TParams parameters, IEngineProvider<IDigest> digestProvider, int digestSize)
		{
            this.approvedOnlyMode = CryptoServicesRegistrar.IsInApprovedOnlyMode();
			this.parameters = parameters;
			this.digestProvider = digestProvider;
			this.digestSize = digestSize;
		}

		/// <summary>The algorithm details object for calculators made by this factory.</summary>
		public TParams AlgorithmDetails { get { return parameters; } }

		public int DigestLength { get { return digestSize; } }

		/// <summary>
		/// Create a stream calculator for the digest algorithm associated with this factory. The stream
		/// calculator is used for the actual operation of entering the data to be digested
		/// and producing the digest block.
		/// </summary>
		/// <returns>A calculator producing an IBlockResult with the final digest in it.</returns>
		public IStreamCalculator<IBlockResult> CreateCalculator()
		{
            CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "DigestFactory");

			return new DigestCalculator(digestProvider.CreateEngine(EngineUsage.GENERAL));
		}
	}
}

