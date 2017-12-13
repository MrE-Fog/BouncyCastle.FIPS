
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Return type for operators that produce a block of data and an associated recovered message.
    /// </summary>
    public interface IBlockResultWithRecoveredMessage: IBlockResult
	{
        /// <summary>
        /// Return the recovered message associated with this result.
        /// </summary>
        /// <returns>a recovered message object.</returns>
		IRecoveredMessage CollectRecoveredMessage();
	}
}

