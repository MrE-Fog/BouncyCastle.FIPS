using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.OpenPgp.Operators
{
    internal class PgpUtils
    {
        internal static readonly IDictionary<HashAlgorithmTag, DigestAlgorithm> digests = new Dictionary<HashAlgorithmTag, DigestAlgorithm>();

        static PgpUtils()
        {
            digests.Add(HashAlgorithmTag.Sha1, FipsShs.Sha1);
            digests.Add(HashAlgorithmTag.Sha224, FipsShs.Sha224);
            digests.Add(HashAlgorithmTag.Sha256, FipsShs.Sha256);
            digests.Add(HashAlgorithmTag.Sha384, FipsShs.Sha384);
            digests.Add(HashAlgorithmTag.Sha512, FipsShs.Sha512);
        }
    }
}
