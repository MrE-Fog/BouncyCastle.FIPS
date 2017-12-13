
namespace Org.BouncyCastle.Crypto
{
    internal interface IEncryptorBuilderProvider<A>
    {
        ICipherBuilder<A> CreateEncryptorBuilder(A algorithmDetails);
    }
}
