
namespace Org.BouncyCastle.OpenSsl
{
    internal interface PemKeyPairParser
    {
        PemKeyPair Parse(byte[] data);
    }
}
