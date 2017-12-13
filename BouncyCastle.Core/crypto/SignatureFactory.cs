using System;

namespace Org.BouncyCastle.Crypto
{
	using Org.BouncyCastle.Crypto.Internal;
	using Org.BouncyCastle.Security;

	internal class SignatureFactory<TParams>: ISignatureFactory<TParams>
	{
		private readonly TParams parameters;
		private readonly IEngineProvider<ISigner> signerProvider;

		internal SignatureFactory(TParams parameters, IEngineProvider<ISigner> signerProvider)
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
		public IStreamCalculator<IBlockResult> CreateCalculator()
		{
			return new SignatureCalculator(signerProvider.CreateEngine(EngineUsage.SIGNING));
		}
	}
}

