
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// General service interface for block ciphers that can be used with AEAD algorithms.
    /// </summary>
    public interface IAeadBlockCipherService: IBlockCipherService, IAeadCipherService
    {
    }
}
