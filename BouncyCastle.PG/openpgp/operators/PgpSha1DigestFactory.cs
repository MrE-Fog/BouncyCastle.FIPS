using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.OpenPgp.Operators.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.OpenPgp.Operators
{
    public class PgpSha1DigestFactory : IDigestFactory<PgpDigestTypeIdentifier>
    {
        private readonly PgpDigestTypeIdentifier sha1Id = new PgpDigestTypeIdentifier(Bcpg.HashAlgorithmTag.Sha1);
        private readonly IDigestFactory<FipsShs.Parameters> sha1Fact = CryptoServicesRegistrar.CreateService(FipsShs.Sha1);

        public PgpDigestTypeIdentifier AlgorithmDetails
        {
            get
            {
                return sha1Id;
            }
        }

        public int DigestLength
        {
            get
            {
                return sha1Fact.DigestLength;
            }
        }

        public IStreamCalculator<IBlockResult> CreateCalculator()
        {
            return sha1Fact.CreateCalculator();
        }
    }
}
