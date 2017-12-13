namespace Org.BouncyCastle.Crypto
{
	/// <summary>
	/// Base interface for operator factories that create stream-based MAC calculators.
	/// </summary>
	public interface IMacFactory<out A>
	{
		/// <summary>The algorithm details object for calculators made by this factory.</summary>
		A AlgorithmDetails { get ; }

		/// <summary>Return the size of the MAC associated with this factory.</summary>
		/// <returns>The length of the MAC produced by this calculators from this factory in bytes.</returns>
		int MacLength { get; }

		/// <summary>
		/// Create a stream calculator for the MAC associated with this factory. The stream
		/// calculator is used for the actual operation of entering the data into the MAC calculator
		/// and producing the MAC block.
		/// </summary>
		/// <returns>A calculator producing an IBlockResult with the final MAC in it.</returns>
		IStreamCalculator<IBlockResult> CreateCalculator();
	}
}