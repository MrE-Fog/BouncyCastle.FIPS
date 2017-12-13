namespace Org.BouncyCastle.Crypto.Paddings
{
    /// <summary>
    /// Block cipher padders are expected to conform to this interface
    /// </summary>
    public interface IBlockCipherPadding
    {
        /// <summary>
        /// Return the name of the algorithm the cipher implements.
        /// </summary>
        /// <returns>
        /// The name of the algorithm the cipher implements.
        /// </returns>
        string PaddingName { get; }

        /// <summary>
        /// Add the pad bytes to the passed in block, returning the number of bytes added.
        /// </summary>
        /// <returns>
        /// The number of pad bytes added.
        /// </returns>
        int AddPadding(byte[] input, int inOff);

        /// <summary>
        /// Return the number of pad bytes present in the block.
        /// </summary>
        /// <returns>
        /// The number of pad bytes present in the block.
        /// </returns> 
        /// <exception cref="InvalidCipherTextException">If the padding is badly formed or invalid</exception>
        int PadCount(byte[] input);
    }

}
