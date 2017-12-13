
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Extension to ISignatureFactory which allows for recovery of the calculated message digest.
    /// </summary>
    /// <typeparam name="A">Configuration parameters used to create the factory.</typeparam>
	public interface ISignatureWithDigestFactory<out A>: ISignatureFactory<A>
	{
		/// <summary>
		/// Create a stream calculator for this signature factory. The stream
		/// calculator is used for the actual operation of entering the data to be signed
		/// and producing the signature block and its associated digest.
		/// </summary>
		/// <returns>A calculator producing an IBlockResultWithRecovered with a signature and the calculated digest in it.</returns>
		IStreamCalculator<IBlockResultWithDigest> CreateCalculatorWithDigest();
	}
}

