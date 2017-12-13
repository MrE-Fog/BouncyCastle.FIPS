using System;

namespace Org.BouncyCastle.Crypto
{
	using Org.BouncyCastle.Crypto.Internal;
	using Org.BouncyCastle.Security;

	internal class MacFactory<TParams>: IMacFactory<TParams>
	{
		private readonly TParams parameters;
		private readonly int macLength;
		private readonly IEngineProvider<IMac> macProvider;

		internal MacFactory(TParams parameters, IEngineProvider<IMac> macProvider, int macLength)
		{
            this.parameters = parameters;
            this.macProvider = macProvider;
            this.macLength = macLength;
        }

        /// <summary>The algorithm details object for calculators made by this factory.</summary>
        public TParams AlgorithmDetails { get { return parameters; } }

		public int MacLength { get { return macLength; } }

        /// <summary>
        /// Create a stream calculator for the digest algorithm associated with this factory. The stream
        /// calculator is used for the actual operation of entering the data to be digested
        /// and producing the digest block.
        /// </summary>
        /// <returns>A calculator producing an IBlockResult with the final digest in it.</returns>
        public IStreamCalculator<IBlockResult> CreateCalculator()
        {
            return new MacCalculator(macProvider.CreateEngine(EngineUsage.GENERAL));
        }
	}
}

