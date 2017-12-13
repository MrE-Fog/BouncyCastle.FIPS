
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// The basic algorithm marker.
    /// </summary>
	public class Algorithm
	{
		private readonly string name;
		private readonly AlgorithmMode mode;

		internal Algorithm (string name): this(name, AlgorithmMode.NONE)
		{
		}

		internal Algorithm (Algorithm algorithm, AlgorithmMode mode) : this(algorithm.Name, mode)
		{
		}

		internal Algorithm (string name, AlgorithmMode mode)
		{
			this.name = name;
			this.mode = mode;
		}

        /// <summary>
        /// Return a readable version of the algorithm name.
        /// </summary>
		public string Name {
			get { return name; }
		}

        /// <summary>
        /// Return any algorithm mode associated with this algorithm marker.
        /// </summary>
		public AlgorithmMode Mode {
			get { return mode; }
		}
    }	
}

