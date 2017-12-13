using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
	/// <summary>
	/// Container class for DSA domain parameters.
	/// </summary>
	public class DsaDomainParameters
	{
		private BigInteger g;
		private BigInteger q;
		private BigInteger p;
		private DsaValidationParameters validation;

		public DsaDomainParameters(
			BigInteger p,
			BigInteger q,
			BigInteger g)
		{
			this.g = g;
			this.p = p;
			this.q = q;
		}

		public DsaDomainParameters(
			BigInteger p,
			BigInteger q,
			BigInteger g,
			DsaValidationParameters validationParameters)
		{
			this.g = g;
			this.p = p;
			this.q = q;
			this.validation = validationParameters;
		}

		public BigInteger P
		{
			get {
				return p;
			}
		}

		public BigInteger Q
		{
			get {
				return q;
			}
		}

		public BigInteger G
		{
			get {
				return g;
			}
		}

		public DsaValidationParameters ValidationParameters
		{
			get {
				return validation;
			}
		}

		public override bool Equals(
			Object obj)
		{
			if (!(obj is DsaDomainParameters))
			{
				return false;
			}

			DsaDomainParameters pm = (DsaDomainParameters)obj;

			return (pm.P.Equals(p) && pm.Q.Equals(q) && pm.G.Equals(g));
		}

		public override int GetHashCode()
		{
			int result = g.GetHashCode();
			result = 31 * result + p.GetHashCode();
			result = 31 * result + q.GetHashCode();
			return result;
		}
	}
}

