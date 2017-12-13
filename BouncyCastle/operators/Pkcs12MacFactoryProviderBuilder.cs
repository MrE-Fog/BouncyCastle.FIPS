using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Operators.Parameters;

namespace Org.BouncyCastle.Operators
{
    public class Pkcs12MacFactoryProviderBuilder
    {
        public IMacFactoryProvider<Pkcs12MacAlgDescriptor> Build(char[] password)
        {
            return new Pkcs12MacFactoryProvider(password);
        }

        private class Pkcs12MacFactoryProvider : IMacFactoryProvider<Pkcs12MacAlgDescriptor>
        {
            private readonly char[] password;

            internal Pkcs12MacFactoryProvider(char[] password)
            {
                this.password = password;
            }

            public IMacFactory<Pkcs12MacAlgDescriptor> CreateMacFactory(Pkcs12MacAlgDescriptor algorithmDetails)
            {
                return new Pkcs12MacFactory(algorithmDetails, password);
            }
        }
    }
}
