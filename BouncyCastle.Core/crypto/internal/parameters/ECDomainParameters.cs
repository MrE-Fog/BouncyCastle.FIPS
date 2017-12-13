using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Internal.Parameters
{
    internal class EcDomainParameters
    {
        internal ECCurve     curve;
        internal byte[]      seed;
        internal ECPoint     g;
        internal BigInteger  n;
        internal BigInteger  h;

        public EcDomainParameters(
            ECCurve     curve,
            ECPoint     g,
            BigInteger  n)
            : this(curve, g, n, BigInteger.One)
        {
        }

        public EcDomainParameters(
            ECCurve     curve,
            ECPoint     g,
            BigInteger  n,
            BigInteger  h)
            : this(curve, g, n, h, null)
        {
        }

        public EcDomainParameters(
            ECCurve     curve,
            ECPoint     g,
            BigInteger  n,
            BigInteger  h,
            byte[]      seed)
        {
            if (curve == null)
                throw new ArgumentNullException("curve");
            if (g == null)
                throw new ArgumentNullException("g");
            if (n == null)
                throw new ArgumentNullException("n");
            if (h == null)
                throw new ArgumentNullException("h");

            this.curve = curve;
            this.g = g.Normalize();
            this.n = n;
            this.h = h;
            this.seed = Arrays.Clone(seed);
        }

        public ECCurve Curve
        {
            get { return curve; }
        }

        public ECPoint G
        {
            get { return g; }
        }

        public BigInteger N
        {
            get { return n; }
        }

        public BigInteger H
        {
            get { return h; }
        }

        public byte[] GetSeed()
        {
            return Arrays.Clone(seed);
        }

        public override bool Equals(
            object obj)
        {
            if (obj == this)
                return true;

            EcDomainParameters other = obj as EcDomainParameters;

            if (other == null)
                return false;

            return Equals(other);
        }

        protected bool Equals(
            EcDomainParameters other)
        {
            return curve.Equals(other.curve)
                &&	g.Equals(other.g)
                &&	n.Equals(other.n)
                &&	h.Equals(other.h)
                &&	Arrays.AreEqual(seed, other.seed);
        }

        public override int GetHashCode()
        {
            return curve.GetHashCode()
                ^	g.GetHashCode()
                ^	n.GetHashCode()
                ^	h.GetHashCode()
                ^	Arrays.GetHashCode(seed);
        }
    }

}