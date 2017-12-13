using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Cms
{
    public interface IRecipientInfoGenerator
    {
        RecipientInfo Generate(ISymmetricKey encKey);
    }
}