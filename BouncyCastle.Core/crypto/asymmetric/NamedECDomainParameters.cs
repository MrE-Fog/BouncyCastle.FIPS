using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Internal.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
	/// <summary>
	/// EC domain parameters associated with a specific object identifier.
	/// </summary>
	public class NamedECDomainParameters: ECDomainParameters
	{
		private DerObjectIdentifier id;

		/// <summary>
		/// Constructor that assumes the co-factor h is 1.
		/// </summary>
		/// <param name="id">The object identifier that represents these parameters.</param>
		/// <param name="curve">The curve for these domain parameters.</param>
		/// <param name="G">The base point G for the domain parameters.</param>
		/// <param name="n">The order for the domain parameters.</param>
		public NamedECDomainParameters(
			DerObjectIdentifier id,
			ECCurve curve,
			ECPoint G,
			BigInteger n): this(id, curve, G, n, BigInteger.One, null)
		{
		}
			
		/// <summary>
		/// Constructor with explicit co-factor.
		/// </summary>
		/// <param name="id">The object identifier that represents these parameters.</param>
		/// <param name="curve">The curve for these domain parameters.</param>
		/// <param name="G">The base point G for the domain parameters.</param>
		/// <param name="n">The order for the domain parameters.</param>
		/// <param name="h">The co-factor.</param>
		public NamedECDomainParameters(
			DerObjectIdentifier id,
			ECCurve curve,
			ECPoint G,
			BigInteger n,
			BigInteger h): this(id, curve, G, n, h, null)
		{
		}

		/// <summary>
		/// Constructor with explicit co-factor and generation seed.
		/// </summary>
		/// <param name="id">The object identifier that represents these parameters.</param>
		/// <param name="curve">The curve for these domain parameters.</param>
		/// <param name="G">The base point G for the domain parameters.</param>
		/// <param name="n">The order for the domain parameters.</param>
		/// <param name="h">The co-factor.</param>
		/// <param name="seed">The seed value used to generate the domain parameters.</param>
		public NamedECDomainParameters(
			DerObjectIdentifier id,
			ECCurve curve,
			ECPoint G,
			BigInteger n,
			BigInteger h,
			byte[] seed): base(curve, G, n, h, seed)
		{
			this.id = id;
		}
			
		/// <summary>
		/// Return object identifier that identifies these parameters.
		/// </summary>
		/// <value>The OID that names this parameter set.</value>
		public DerObjectIdentifier ID
		{
			get {
				return id;
			}
		}

		// for the purposes of equality and hashCode we ignore the prescence of the name.
		public override bool Equals(object o)
		{
			return base.Equals(o);
		}

		public override int GetHashCode()
		{
			return base.GetHashCode();
		}
	}
}

