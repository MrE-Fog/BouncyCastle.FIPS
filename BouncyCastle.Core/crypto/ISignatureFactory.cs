
namespace Org.BouncyCastle.Crypto
{
	/// <summary>
	/// Base interface for operator factories that create stream-based signature calculators.
	/// </summary>
    /// <typeparam name="A">Configuration parameters used to create the factory.</typeparam>
	public interface ISignatureFactory<out A>
	{
		/// <summary>The algorithm details object for calculators made by this factory.</summary>
        A AlgorithmDetails { get ; }

		/// <summary>
		/// Create a stream calculator for the signature algorithm associated with this factory. The stream
		/// calculator is used for the actual operation of entering the data to be signed
		/// and producing the signature block.
		/// </summary>
		/// <returns>A calculator producing an IBlockResult with the final signature in it.</returns>
		IStreamCalculator<IBlockResult> CreateCalculator();
	}
}


