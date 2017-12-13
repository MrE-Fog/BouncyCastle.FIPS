using System;

using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base class for symmetric secret keys.
    /// </summary>
	public class SymmetricSecretKey: ISymmetricKey
	{
		private int        hashCode;
		private Algorithm algorithm;
		private byte[] bytes;

        /// <summary>
        /// Base constructor.
        /// </summary>
        /// <param name="algorithm">The algorithm this secret key is associated with.</param>
        /// <param name="bytes">The bytes representing the key's value.</param>
        public SymmetricSecretKey(Algorithm algorithm, byte[] bytes)
		{
			this.algorithm = algorithm;
			this.hashCode = calculateHashCode();
			this.bytes = Arrays.Clone(bytes);
		}

        /// <summary>
        /// Base constructor for a specific algorithm associated with a parameter set.
        /// </summary>
        /// <param name="parameterSet">The parameter set with the algorithm this secret key is associated with.</param>
        /// <param name="bytes">The bytes representing the key's value.</param>
        public SymmetricSecretKey(IParameters<Algorithm> parameterSet, byte[] bytes)
		{
			this.algorithm = parameterSet.Algorithm;
			this.hashCode = calculateHashCode();
			this.bytes = Arrays.Clone(bytes);
		}

        /// <summary>
        /// Specific constructor for a SHS authentication parameters.
        /// </summary>
        /// <param name="parameterSet">The parameter set with the algorithm this secret key is associated with.</param>
        /// <param name="bytes">The bytes representing the key's value.</param>
        public SymmetricSecretKey(FipsShs.AuthenticationParameters parameterSet, byte[] bytes)
		{
			this.algorithm = parameterSet.Algorithm;
			this.hashCode = calculateHashCode();
			this.bytes = Arrays.Clone(bytes);
		}

        ~SymmetricSecretKey()
        {
            if (bytes != null)
            {
                Array.Clear(bytes, 0, bytes.Length);
            }
        }

        /// <summary>
        /// Return the algorithm this secret key is for.
        /// </summary>
        public Algorithm Algorithm
		{
			get { return algorithm; }
		}

        /// <summary>
        /// Return the bytes representing this keys value.
        /// </summary>
        /// <returns>The bytes making up this key.</returns>
        public byte[] GetKeyBytes()
		{
			return Arrays.Clone(bytes);
		}

		public override bool Equals(object o)
		{
			if (this == o)
			{
				return true;
			}
				
			SymmetricSecretKey other = o as SymmetricSecretKey;

			if (other == null)
			{
				return false;
			}

			if (!Algorithm.Equals(other.Algorithm))
			{
				return false;
			}

			if (!Array.Equals(bytes, other.bytes))
			{
				return false;
			}

			return true;
		}
			
		public override int GetHashCode()
		{
			return hashCode;
		}

		private int calculateHashCode()
		{
			int result = Algorithm.GetHashCode();
			result = 31 * result + Arrays.GetHashCode(bytes);
			return result;
		}
	}
}

