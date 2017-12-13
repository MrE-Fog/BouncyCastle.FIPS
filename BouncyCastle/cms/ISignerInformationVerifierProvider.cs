
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Cms
{
    public interface ISignerInformationVerifierProvider
    {
        bool IsRawSigner { get; }

        IVerifierFactory<AlgorithmIdentifier> CreateVerifierFactory(AlgorithmIdentifier signatureAlgorithmID, AlgorithmIdentifier digestAlgorithmID);

        IDigestFactory<AlgorithmIdentifier> CreateDigestFactory(AlgorithmIdentifier digestAlgorithmID);
    }
}
