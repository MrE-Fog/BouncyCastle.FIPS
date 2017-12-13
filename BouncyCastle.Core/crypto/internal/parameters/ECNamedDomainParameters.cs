using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Crypto.Internal.Parameters
{
	internal class ECNamedDomainParameters: EcDomainParameters
	{
		private readonly DerObjectIdentifier name;

		public ECNamedDomainParameters(DerObjectIdentifier name, ECCurve curve, ECPoint G, BigInteger n, BigInteger h, byte[] seed)
		: base(curve, G, n, h, seed)
		{

			this.name = name;
		}

		public DerObjectIdentifier getName()
		{
			return name;
		}

		// for the purposes of equality and hashCode we ignore the prescence of the name.
		public override bool Equals(Object o)
		{
			return base.Equals(o);
		}

		public override int GetHashCode()
		{
			return base.GetHashCode();
		}
	}
}

