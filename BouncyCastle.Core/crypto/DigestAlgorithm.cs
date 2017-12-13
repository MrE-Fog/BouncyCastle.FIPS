
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Algorithm marker specifically for use with message digests and HMACs.
    /// </summary>
	public class DigestAlgorithm: Algorithm
	{
		internal DigestAlgorithm (string name): base(name, AlgorithmMode.NONE)
		{
		}

		internal DigestAlgorithm (string name, AlgorithmMode mode): base(name, mode)
		{
		}
	}
}

