using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.General;
using Org.BouncyCastle.Operators.Parameters;

namespace Org.BouncyCastle.Operators
{
    internal class Pkcs12MacFactory : IMacFactory<Pkcs12MacAlgDescriptor>
    {
        private readonly IMacFactory<FipsShs.AuthenticationParameters> baseFactory;
        private readonly Pkcs12MacAlgDescriptor algDetails;

        internal Pkcs12MacFactory(Pkcs12MacAlgDescriptor algDetails, char[] password)
        {
            this.algDetails = algDetails;

            DigestAlgorithm prf = (DigestAlgorithm)Utils.digestTable[algDetails.DigestAlgorithm.Algorithm];

            IPasswordBasedDeriver<Pbkd.PbkdParameters> deriver = CryptoServicesRegistrar.CreateService(Pbkd.Pkcs12).From(PasswordConverter.PKCS12, password)
                .WithPrf(prf).WithSalt(algDetails.GetIV()).WithIterationCount(algDetails.IterationCount).Build();

            this.baseFactory = CryptoServicesRegistrar.CreateService(new FipsShs.Key(FipsShs.Sha1HMac, deriver.DeriveKey(TargetKeyType.MAC, (int)Utils.digestSize[prf]))).CreateMacFactory((FipsShs.AuthenticationParameters)Utils.pkcs12MacIds[prf]);
        }

        public Pkcs12MacAlgDescriptor AlgorithmDetails
        {
            get
            {
                return algDetails;
            }
        }

        public int MacLength
        {
            get
            {
                return baseFactory.MacLength;
            }
        }

        public IStreamCalculator<IBlockResult> CreateCalculator()
        {
            return baseFactory.CreateCalculator();
        }
    }
}
