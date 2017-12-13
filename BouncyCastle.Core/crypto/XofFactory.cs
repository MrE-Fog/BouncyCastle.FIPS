using Org.BouncyCastle.Crypto.Internal;

namespace Org.BouncyCastle.Crypto
{
	internal class XofFactory<TParams>: IXofFactory<TParams>
	{
        private readonly bool approvedOnlyMode;
        private readonly TParams parameters;
		private readonly IEngineProvider<IXof> xofProvider;

		internal XofFactory(TParams parameters, IEngineProvider<IXof> xofProvider)
		{
            this.approvedOnlyMode = CryptoServicesRegistrar.IsInApprovedOnlyMode();
            this.parameters = parameters;
			this.xofProvider = xofProvider;
		}

		/// <summary>The algorithm details object for calculators made by this factory.</summary>
		public TParams AlgorithmDetails { get { return parameters; } }

		/// <summary>
		/// Create a stream calculator for the XOF associated with this factory. The stream
		/// calculator is used for the actual operation of entering the data to be processed
		/// and producing the XOF output.
		/// </summary>
		/// <returns>A calculator producing an StreamResult which can be used to read the output from the XOF.</returns>
		public IVariableStreamCalculator<IBlockResult> CreateCalculator()
		{
            CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "XofFactory");

            return new XofCalculator(xofProvider.CreateEngine(EngineUsage.GENERAL));
		}
	}
}
