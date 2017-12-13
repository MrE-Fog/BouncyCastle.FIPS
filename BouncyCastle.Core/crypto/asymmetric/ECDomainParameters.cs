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
	/// Container class for Elliptic Curve domain parameters.
	/// </summary>
	public class ECDomainParameters
	{
		private readonly ECCurve curve;
		private readonly byte[]  seed;
		private readonly ECPoint g;
		private readonly BigInteger n;
		private readonly BigInteger  h;

		/// <summary>
		/// Constructor that assumes the co-factor h is 1.
		/// </summary>
		/// <param name="curve">The curve for these domain parameters.</param>
		/// <param name="G">The base point G for the domain parameters.</param>
		/// <param name="n">The order for the domain parameters.</param>
		public ECDomainParameters(
			ECCurve curve,
			ECPoint G,
			BigInteger n): this(curve, G, n, BigInteger.One, null)
		{
		}

		/// <summary>
		/// Constructor with explicit co-factor.
		/// </summary>

		/// <param name="curve">The curve for these domain parameters.</param>
		/// <param name="G">The base point G for the domain parameters.</param>
		/// <param name="n">The order for the domain parameters.</param>
		/// <param name="h">The co-factor.</param>
		public ECDomainParameters(
			ECCurve curve,
			ECPoint G,
			BigInteger n,
			BigInteger h): this(curve, G, n, h, null)
		{
		}

		/// <summary>
		/// Constructor with explicit co-factor and generation seed.
		/// </summary>
		/// <param name="curve">The curve for these domain parameters.</param>
		/// <param name="G">The base point G for the domain parameters.</param>
		/// <param name="n">The order for the domain parameters.</param>
		/// <param name="h">The co-factor.</param>
		/// <param name="seed">The seed value used to generate the domain parameters.</param>
		public ECDomainParameters(
			ECCurve curve,
			ECPoint G,
			BigInteger n,
			BigInteger h,
			byte[] seed)
		{
			this.curve = curve;
			this.g = G.Normalize();
			this.n = n;
			this.h = h;
			this.seed = Arrays.Clone(seed);
		}

		/**
     * Return the curve associated with these domain parameters.
     *
     * @return the domain parameters' curve.
     */
		public ECCurve Curve
		{
			get {
			return curve;
		}
		}

		/**
     * Return the base point associated with these domain parameters.
     *
     * @return the domain parameters' base point.
     */
		public ECPoint G
		{
			get {
				return g;
			}
		}

		/**
     * Return the order associated with these domain parameters.
     *
     * @return the domain parameters' order.
     */
		public BigInteger N
		{
			get {
				return n;
			}
		}

		/**
     * Return the co-factor associated with these domain parameters.
     *
     * @return the domain parameters' co-factor.
     */
		public BigInteger H
		{
			get {
			return h;
		}
		}

		/**
     * Return the generation seed associated with these domain parameters.
     *
     * @return the domain parameters' seed.
     */
		public byte[] GetSeed()
		{
			return Arrays.Clone(seed);
		}
			
		public override bool Equals(Object o)
		{
			if (this == o)
			{
				return true;
			}
			if (!(o is ECDomainParameters))
			{
				return false;
			}

			ECDomainParameters that = (ECDomainParameters)o;

			if (!G.Equals(that.G))
			{
				return false;
			}
			if (!curve.Equals(that.curve))
			{
				return false;
			}
			if (!h.Equals(that.h))
			{
				return false;
			}
			if (!n.Equals(that.n))
			{
				return false;
			}
			// we need to ignore the seed as it will not always be set 

			return true;
		}

		public override int GetHashCode()
		{
			int result = curve.GetHashCode();
			// we need to ignore the seed as it will not always be set 
			result = 31 * result + G.GetHashCode();
			result = 31 * result + n.GetHashCode();
			result = 31 * result + h.GetHashCode();
			return result;
		}

		static internal ECDomainParameters DecodeCurveParameters(AlgorithmIdentifier algId)
		{
			if (!algId.Algorithm.Equals(X9ObjectIdentifiers.IdECPublicKey))
			{
				throw new ArgumentException("Unknown algorithm type: " + algId.Algorithm);
			}

			X962Parameters parameters = X962Parameters.GetInstance(algId.Parameters);

			X9ECParameters x9;

			if (parameters.IsNamedCurve)
			{
				DerObjectIdentifier oid = (DerObjectIdentifier)parameters.Parameters;

				x9 = CustomNamedCurves.GetByOid(oid);
				if (x9 == null)
				{
					x9 = ECNamedCurveTable.GetByOid(oid);
				}
				return new NamedECDomainParameters(oid, x9.Curve, x9.G, x9.N, x9.H, x9.GetSeed());
			}
			else if (!parameters.IsImplicitlyCA)
			{
				x9 = X9ECParameters.GetInstance(parameters.Parameters);
				return new ECDomainParameters(x9.Curve, x9.G, x9.N, x9.H, x9.GetSeed());
			}
			else
			{
				return null;
				//return new ECImplicitDomainParameters(CryptoServicesRegistrar.<ECDomainParameters>getProperty(CryptoServicesRegistrar.Property.EC_IMPLICITLY_CA));
			}
		}
	}
}

