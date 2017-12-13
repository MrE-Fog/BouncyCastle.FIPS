
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Service interface for NewHope style key material exchange generators.
    /// </summary>
    public interface IExchangePairGeneratorService
    {
        /// <summary>
        /// Generate an exchange pair based on the sender public key.
        /// </summary>
        /// <param name="senderPublicKey">The public key of the exchange initiator.</param>
        /// <returns>An ExchangePair derived from the sender public key.</returns>
        ExchangePair GenerateExchange(IAsymmetricPublicKey senderPublicKey);
    }
}
