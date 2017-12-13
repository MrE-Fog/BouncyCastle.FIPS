using System;

using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
    /// <summary>
    /// Base class for DH keys.
    /// </summary>
	public abstract class AsymmetricDHKey
        : IAsymmetricKey
    {
        private static readonly ISet dsaOids = new HashSet();

        static AsymmetricDHKey()
        {
            dsaOids.Add(X9ObjectIdentifiers.IdDsa);
            dsaOids.Add(X9ObjectIdentifiers.IdDsaWithSha1);
            dsaOids.Add(OiwObjectIdentifiers.DsaWithSha1);
        }

        private readonly bool approvedModeOnly;
        private readonly Algorithm algorithm;
        private readonly DHDomainParameters domainParameters;

        internal AsymmetricDHKey(Algorithm algorithm, DHDomainParameters domainParameters)
        {
            this.approvedModeOnly = CryptoServicesRegistrar.IsInApprovedOnlyMode();
            this.algorithm = algorithm;
            this.domainParameters = domainParameters;
        }

        internal AsymmetricDHKey(Algorithm algorithm, AlgorithmIdentifier algorithmIdentifier)
        {
            this.approvedModeOnly = CryptoServicesRegistrar.IsInApprovedOnlyMode();
            this.algorithm = algorithm;
            this.domainParameters = DecodeDomainParameters(algorithmIdentifier);
        }

        private static DHDomainParameters DecodeDomainParameters(AlgorithmIdentifier algorithmIdentifier)
        {
            DerObjectIdentifier id = algorithmIdentifier.Algorithm;
            Asn1Encodable parameters = algorithmIdentifier.Parameters;

            if (parameters == null)
            {
                throw new ArgumentException("AlgorithmIdentifier parameters cannot be empty");
            }

            if (id.Equals(OiwObjectIdentifiers.ElGamalAlgorithm))
            {
                ElGamalParameter elg = ElGamalParameter.GetInstance(parameters);

                return new DHDomainParameters(elg.P, elg.G);
            }

            // we need the PKCS check to handle older keys marked with the X9 oid.
            if (id.Equals(PkcsObjectIdentifiers.DhKeyAgreement) || KeyUtils.IsDHPkcsParam(parameters))
            {
                DHParameter dhParameters = DHParameter.GetInstance(parameters);

                if (dhParameters .L != null)
                {
                    return new DHDomainParameters(dhParameters.P, null, dhParameters.G, dhParameters.L.IntValue);
                }
                else
                {
                    return new DHDomainParameters(dhParameters.P, dhParameters.G);
                }
            }
            else if (id.Equals(X9ObjectIdentifiers.DHPublicNumber))
            {
                Asn1.X9.DHDomainParameters dhParameters = Asn1.X9.DHDomainParameters.GetInstance(parameters);

                if (dhParameters.ValidationParms != null)
                {
                    return new DHDomainParameters(GetValue(dhParameters.P), GetValue(dhParameters.Q), GetValue(dhParameters.G), GetValue(dhParameters.J),
                        new DHValidationParameters(dhParameters.ValidationParms.Seed.GetBytes(), dhParameters.ValidationParms.PgenCounter.Value.IntValue));
                }
                else
                {
                    return new DHDomainParameters(GetValue(dhParameters.P), GetValue(dhParameters.Q), GetValue(dhParameters.G), GetValue(dhParameters.J), null);
                }
            }
            else
            {
                throw new ArgumentException("Unknown algorithm type: " + id);
            }
        }

        private static BigInteger GetValue(DerInteger i)
        {
            if (i != null)
            {
                return i.Value;
            }

            return null;
        }

        /// <summary>
        /// Return the algorithm this DSA key is for.
        /// </summary>
        /// <value>The key's algorithm.</value>
        public virtual Algorithm Algorithm
        {
            get { return algorithm; }
        }

        /// <summary>
        /// Return the DH domain parameters associated with this key.
        /// </summary>
        /// <value>The DH domain parameters for this key.</value>
        public virtual DHDomainParameters DomainParameters
        {
            get { return domainParameters; }
        }

        /// <summary>
        /// Return an ASN.1 encoded representation of the implementing key.
        /// </summary>
        /// <returns>An encoded representation of the key.</returns>
        public abstract byte[] GetEncoded();

        internal virtual void CheckApprovedOnlyModeStatus()
        {
            if (approvedModeOnly != CryptoServicesRegistrar.IsInApprovedOnlyMode())
                throw new CryptoUnapprovedOperationError("No access to key in current thread.");
        }
    }
}

