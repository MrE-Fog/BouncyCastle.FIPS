
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for operator factories that create eXpandable Output Functions (XOF).
    /// </summary>
    /// <typeparam name="A">Type for the configuration parameters for the verifier this provider produces.</typeparam>
    public interface IXofFactory<out A>
	{
		/// <summary>The algorithm details object for calculators made by this factory.</summary>
		A AlgorithmDetails { get ; }

		/// <summary>
		/// Create a stream calculator for the XOF associated with this factory. The stream
		/// calculator is used for the actual operation of entering the data to be processed
		/// and producing the XOF output.
		/// </summary>
		/// <returns>A calculator producing an IBlockResult containing the output from the XOF.</returns>
		IVariableStreamCalculator<IBlockResult> CreateCalculator();
	}
}

