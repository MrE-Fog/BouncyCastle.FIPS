using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Cms
{
    interface IKeyTransRecipient: IRecipient
    {
        RecipientOperator GetRecipientOperator(AlgorithmIdentifier keyEncAlg, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentKey);
    }
}
