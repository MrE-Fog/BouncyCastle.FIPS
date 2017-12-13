
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for a recovered message object.
    /// </summary>
	public interface IRecoveredMessage
	{
        /// <summary>
        /// Return true if the full message has been recovered, false if only partially.
        /// </summary>
		bool IsFullMessage { get; }

        /// <summary>
        /// Return a byte array representing the message data recovered.
        /// </summary>
        /// <returns>The recovered content.</returns>
        byte[] GetContent();
	}
}

