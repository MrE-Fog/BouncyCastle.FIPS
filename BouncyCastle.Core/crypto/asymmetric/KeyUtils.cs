using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using System.Threading;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
	internal class KeyUtils
	{
		public KeyUtils ()
		{
		}

        internal static BigInteger Validated(DHDomainParameters dhParams, BigInteger y)
        {
            if (dhParams.Q != null)
            {
                //  "SP 800-56A ASSURANCES", "The module is performing SP 800-56A Assurances self-test"
                //  "CONDITIONAL TEST", "SP 800-56A ASSURANCES CHECK", "Invoke SP 800-56A Assurances test"
                if (BigInteger.One.Equals(y.ModPow(dhParams.Q, dhParams.P)))
                {
                    //  "SP 800-56A ASSURANCES CHECK", "CONDITIONAL TEST", "SP 800-56A Assurances test successful"
                    return y;
                }
                //  "SP 800-56A ASSURANCES CHECK", "CONDITIONAL TEST", "SP 800-56A Assurances test failed"
                throw new ArgumentException("Y value does not appear to be in correct group");
            }
            else
            {
                return y;         // we can't validate without Q.
            }
        }

        internal static bool IsDHPkcsParam(Asn1Encodable parameters)
        {
            Asn1Sequence seq = Asn1Sequence.GetInstance(parameters);

            if (seq.Count == 2)
            {
                return true;
            }

            if (seq.Count > 3)
            {
                return false;
            }

            DerInteger l = DerInteger.GetInstance(seq[2]);
            DerInteger p = DerInteger.GetInstance(seq[0]);

            if (l.Value.CompareTo(BigInteger.ValueOf(p.Value.BitLength)) > 0)
            {
                return false;
            }

            return true;
        }

        internal static BigInteger Validated(DsaDomainParameters dsaParams, BigInteger y)
		{
			if (dsaParams != null)
			{
				// FSM_STATE:5.8, "FIPS 186-3/SP 800-89 ASSURANCES", "The module is performing FIPS 186-3/SP 800-89 Assurances self-test"
				// FSM_TRANS:5.9, "CONDITIONAL TEST", "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "Invoke FIPS 186-3/SP 800-89 Assurances test"
				if (BigInteger.Two.CompareTo(y) <= 0 && dsaParams.P.Subtract(BigInteger.Two).CompareTo(y) >= 0
					&& BigInteger.One.Equals(y.ModPow(dsaParams.Q, dsaParams.P)))
				{
					// FSM_TRANS:5.10, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "CONDITIONAL TEST", "FIPS 186-3/SP 800-89 Assurances test successful"
					return y;
				}

				throw new ArgumentException("Y value does not appear to be in correct group");
			}
			else
			{
				return y;         // we can't validate without params, fortunately we can't use the key either...
			}
		}

		internal static BigInteger Validated(BigInteger modulus, BigInteger publicExponent)
		{
			// FSM_STATE:5.8, "FIPS 186-3/SP 800-89 ASSURANCES", "The module is performing FIPS 186-3/SP 800-89 Assurances self-test"
			// FSM_TRANS:5.9, "CONDITIONAL TEST", "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "Invoke FIPS 186-3/SP 800-89 Assurances test"
			if ((publicExponent.IntValue & 1) == 0)
			{
				throw new ArgumentException("RSA publicExponent is even");
			}

            return ValidatedModulus(modulus);
        }

        internal static BigInteger ValidatedModulus(BigInteger modulus)
        {
            // if there is already a marker for this modulus it has already been validated, or we've already loaded it with a private key.
            // skip the tests
            if (!AsymmetricRsaKey.IsAlreadySeen(modulus))
			{
				if ((modulus.IntValue & 1) == 0)
				{
					throw new ArgumentException("RSA modulus is even");
				}

				// the value is the product of the 132 smallest primes from 3 to 751
				if (!modulus.Gcd(new BigInteger("145188775577763990151158743208307020242261438098488931355057091965" +
					"931517706595657435907891265414916764399268423699130577757433083166" +
					"651158914570105971074227669275788291575622090199821297575654322355" +
					"049043101306108213104080801056529374892690144291505781966373045481" +
					"8359472391642885328171302299245556663073719855")).Equals(BigInteger.One))
				{
					throw new ArgumentException("RSA modulus has a small prime factor");
				}

				// Use the same iterations as if we were testing a candidate p or q value with error probability 2^-100
				int bits = modulus.BitLength;
				int iterations = bits >= 1536 ? 3
					: bits >= 1024 ? 4
					: bits >= 512 ? 7
					: 50;

				// SP 800-89 requires use of an approved DRBG - we construct directly from base to avoid context issues
				SecureRandom testRandom = new FipsDrbg.Base(FipsDrbg.Sha256).FromEntropySource(new SecureRandom(), false)
					.Build(Pack.UInt64_To_LE((ulong)DateTime.Now.Ticks), false, Strings.ToByteArray(Thread.CurrentThread.ToString()));
	
				Primes.MROutput mr = Primes.EnhancedMRProbablePrimeTest(modulus, testRandom, iterations);
				if (!mr.IsProvablyComposite)
				{
					throw new ArgumentException("RSA modulus is not composite");
				}
				if (!mr.IsNotPrimePower)
				{
					throw new ArgumentException("RSA modulus is a power of a prime");
				}
			}
			// FSM_TRANS:5.10, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "CONDITIONAL TEST", "FIPS 186-3/SP 800-89 Assurances test successful"

			return modulus;
		}

		internal static ECPoint Validated(ECPoint q)
		{
			// FSM_STATE:5.8, "FIPS 186-3/SP 800-89 ASSURANCES", "The module is performing FIPS 186-3/SP 800-89 Assurances self-test"
			// FSM_TRANS:5.9, "CONDITIONAL TEST", "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "Invoke FIPS 186-3/SP 800-89 Assurances test"
			if (q == null)
			{
				throw new ArgumentException("Point has null value");
			}

			if (q.IsInfinity)
			{
				throw new ArgumentException("Point at infinity");
			}

			q = q.Normalize();

			if (!q.IsValid())
			{
				throw new ArgumentException("Point not on curve");
			}

			// FSM_TRANS:5.10, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "CONDITIONAL TEST", "FIPS 186-3/SP 800-89 Assurances test successful"
			return q;
		}

		internal static bool IsNotNull(Asn1Encodable parameters)
		{
			return parameters != null && !DerNull.Instance.Equals(parameters.ToAsn1Object());
		}

		internal static byte[] GetEncodedInfo(Asn1Encodable info)
		{
			try
			{
				return info.GetEncoded(Asn1Encodable.Der);
			}
			catch (Exception)
			{
				return null;
			}
		}

		internal static byte[] GetEncodedSubjectPublicKeyInfo(AlgorithmIdentifier algId, Asn1Encodable pubKey)
		{
			try
			{
				SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(algId, pubKey.ToAsn1Object());

				return GetEncodedInfo(info);
			}
			catch (Exception)
			{
				return null;
			}
		}

		internal static byte[] GetEncodedPrivateKeyInfo(AlgorithmIdentifier algId, Asn1Encodable privKey)
		{
			try
			{
				PrivateKeyInfo info = new PrivateKeyInfo(algId, privKey.ToAsn1Object());

				return GetEncodedInfo(info);
			}
			catch (Exception)
			{
				return null;
			}
		}

		internal static X962Parameters BuildCurveParameters(ECDomainParameters curveParams)
		{
			X962Parameters          parameters;

			if (curveParams is NamedECDomainParameters)
			{
				parameters = new X962Parameters(((NamedECDomainParameters)curveParams).ID);
			}
			else if (curveParams is ECImplicitDomainParameters)
			{
				parameters = new X962Parameters(DerNull.Instance);
			}
			else
			{
				X9ECParameters ecP = new X9ECParameters(
					curveParams.Curve,
					curveParams.G,
					curveParams.N,
					curveParams.H,
					curveParams.GetSeed());

				parameters = new X962Parameters(ecP);
			}

			return parameters;
		}

		internal static int GetOrderBitLength(ECDomainParameters curveParams)
		{
			return curveParams.N.BitLength;
		}
	}
}

