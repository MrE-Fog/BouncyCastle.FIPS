

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// An extension to ISignatureFactory which adds recovered messages.
    /// </summary>
    /// <typeparam name="A">Configuration parameters used to create the factory.</typeparam>
	public interface ISignatureWithRecoveredMessageFactory<out A>: ISignatureFactory<A>
	{
		/// <summary>
		/// Create a stream calculator for this signature calculator. The stream
		/// calculator is used for the actual operation of entering the data to be signed
		/// and producing the signature block.
		/// </summary>
		/// <returns>A calculator producing an IBlockResultWithRecovered with a signature and the recovered message in it.</returns>
		IStreamCalculator<IBlockResultWithRecoveredMessage> CreateCalculatorWithRecoveredMessage();
	}
}

