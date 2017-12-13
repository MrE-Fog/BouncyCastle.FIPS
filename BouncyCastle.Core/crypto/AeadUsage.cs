
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Enum to specify how the associated data will be introduced into the AEAD cipher
    /// during processing.
    /// </summary>
	public enum AeadUsage {
		AAD_FIRST,
		INPUT_FIRST,
		INTERLEAVE
	}
}

