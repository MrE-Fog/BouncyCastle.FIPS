using Org.BouncyCastle.Crypto.Internal;

namespace Org.BouncyCastle.Crypto
{
	internal class VerifierFactory<TParams>: IVerifierFactory<TParams>
	{
		private readonly TParams parameters;
		private readonly IEngineProvider<ISigner> signerProvider;

		internal VerifierFactory(TParams parameters, IEngineProvider<ISigner> signerProvider)
		{
			this.parameters = parameters;
			this.signerProvider = signerProvider;
		}

		/// <summary>The algorithm details object for calculators made by this factory.</summary>
		public TParams AlgorithmDetails { get { return parameters; } }

		/// <summary>
		/// Create a stream calculator for the signature algorithm associated with this factory. The stream
		/// calculator is used for the actual operation of entering the data to be signed
		/// and producing the signature block.
		/// </summary>
		/// <returns>A calculator producing an IBlockResult with the final signature in it.</returns>
		public IStreamCalculator<IVerifier> CreateCalculator()
		{
			return new VerifierCalculator(signerProvider.CreateEngine(EngineUsage.VERIFICATION));
		}
	}
}

