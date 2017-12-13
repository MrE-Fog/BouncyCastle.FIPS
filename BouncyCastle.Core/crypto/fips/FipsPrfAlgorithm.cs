using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Crypto.Fips
{
    /// <summary>
    /// Specific type for representing FIPS algorithms which act as pseudo-random-functions. 
    /// </summary>
    public class FipsPrfAlgorithm: PrfAlgorithm
    {
        public static readonly FipsPrfAlgorithm Sha1 = new FipsPrfAlgorithm(FipsShs.Sha1.Algorithm);
        public static readonly FipsPrfAlgorithm Sha224 = new FipsPrfAlgorithm(FipsShs.Sha224.Algorithm);
        public static readonly FipsPrfAlgorithm Sha256 = new FipsPrfAlgorithm(FipsShs.Sha256.Algorithm);
        public static readonly FipsPrfAlgorithm Sha384 = new FipsPrfAlgorithm(FipsShs.Sha384.Algorithm);
        public static readonly FipsPrfAlgorithm Sha512 = new FipsPrfAlgorithm(FipsShs.Sha512.Algorithm);

        public static readonly FipsPrfAlgorithm AesCMac = new FipsPrfAlgorithm(FipsAes.CMac.Algorithm);

        public static readonly FipsPrfAlgorithm Sha1HMac = new FipsPrfAlgorithm(FipsShs.Sha1HMac.Algorithm);
        public static readonly FipsPrfAlgorithm Sha224HMac = new FipsPrfAlgorithm(FipsShs.Sha224HMac.Algorithm);
        public static readonly FipsPrfAlgorithm Sha256HMac = new FipsPrfAlgorithm(FipsShs.Sha256HMac.Algorithm);
        public static readonly FipsPrfAlgorithm Sha384HMac = new FipsPrfAlgorithm(FipsShs.Sha384HMac.Algorithm);
        public static readonly FipsPrfAlgorithm Sha512HMac = new FipsPrfAlgorithm(FipsShs.Sha512HMac.Algorithm);

        internal FipsPrfAlgorithm(Algorithm algorithm): base(algorithm)
        {

        }
    }
}
