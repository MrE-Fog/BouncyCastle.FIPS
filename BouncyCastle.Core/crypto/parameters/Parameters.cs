
namespace Org.BouncyCastle.Crypto.Parameters
{
	public class Parameters<TAlg>: IParameters<TAlg> where TAlg: Algorithm
	{
		private readonly TAlg algorithm;

		internal Parameters(TAlg algorithm)
		{
			this.algorithm = algorithm;
		}

		public TAlg Algorithm {
			get { return algorithm; }
		}
    }
}

