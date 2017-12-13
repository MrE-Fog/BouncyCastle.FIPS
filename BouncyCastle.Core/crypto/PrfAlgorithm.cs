
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Specific type for representing algorithms which act as pseudo-random-functions. 
    /// </summary>
    public class PrfAlgorithm
    {
        private readonly Algorithm algorithm;

        internal PrfAlgorithm(Algorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        internal Algorithm BaseAlgorithm {
            get {
                return algorithm;
            }
        }
    }
}
