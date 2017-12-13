using System;
using System.Globalization;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Crypto.Internal.Parameters
{
    internal class ECPublicKeyParameters
        : ECKeyParameters
    {
        private readonly ECPoint q;

        public ECPublicKeyParameters(
            ECPoint				q,
            EcDomainParameters	parameters)
            : this("EC", q, parameters)
        {
        }

        public ECPublicKeyParameters(
            string				algorithm,
            ECPoint				q,
            EcDomainParameters	parameters)
            : base(algorithm, false, parameters)
        {
            if (q == null)
                throw new ArgumentNullException("q");

            this.q = q.Normalize();
        }

        public ECPublicKeyParameters(
            string				algorithm,
            ECPoint				q,
            DerObjectIdentifier publicKeyParamSet)
            : base(algorithm, false, publicKeyParamSet)
        {
            if (q == null)
                throw new ArgumentNullException("q");

            this.q = q.Normalize();
        }

        public ECPoint Q
        {
            get { return q; }
        }

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            ECPublicKeyParameters other = obj as ECPublicKeyParameters;

            if (other == null)
                return false;

            return Equals(other);
        }

        protected bool Equals(
            ECPublicKeyParameters other)
        {
            return q.Equals(other.q) && base.Equals(other);
        }

        public override int GetHashCode()
        {
            return q.GetHashCode() ^ base.GetHashCode();
        }
    }
}
