using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Internal.Generators
{
/**
 * an RSA key pair generator.
 */
internal class RsaKeyPairGenerator: IAsymmetricCipherKeyPairGenerator
    {
    private RsaKeyGenerationParameters param;
    private int iterations;

    public void Init(
        KeyGenerationParameters param)
    {
        this.param = (RsaKeyGenerationParameters)param;
        this.iterations = getNumberOfIterations(this.param.Strength, this.param.Certainty);
    }

    public AsymmetricCipherKeyPair GenerateKeyPair()
    {
        AsymmetricCipherKeyPair result = null;
        bool done = false;

        //
        // p and q values should have a length of half the strength in bits
        //
        int strength = param.Strength;
        int pbitlength = (strength + 1) / 2;
        int qbitlength = strength - pbitlength;
        int mindiffbits = (strength / 2) - 100;
        int minWeight = strength >> 2;

        // for approved mode operation this will never happen, but in case
        // someone is doing something "different" we make sure mindiffbits  is
        // always sensible.
        if (mindiffbits < strength / 3)
        {
            mindiffbits = strength / 3;
        }

        // d lower bound is 2^(strength / 2)
        BigInteger dLowerBound = BigInteger.Two.Pow(strength / 2);
        // squared bound (sqrt(2)*2^(nlen/2-1))^2
        BigInteger squaredBound = BigInteger.One.ShiftLeft(strength - 1);
        // 2^(nlen/2 - 100)
        BigInteger minDiff = BigInteger.One.ShiftLeft(mindiffbits);

        while (!done)
        {
            BigInteger p, q, n, d, e, pSub1, qSub1, gcd, lcm;

            e = param.PublicExponent;

            p = chooseRandomPrime(pbitlength, e, squaredBound);

            //
            // generate a modulus of the required length
            //
            for (;;)
            {
                q = chooseRandomPrime(qbitlength, e, squaredBound);

                // p and q should not be too close together (or equal!)
                BigInteger diff = q.Subtract(p).Abs();
                if (diff.BitLength < mindiffbits || diff.CompareTo(minDiff) <= 0)
                {
                    continue;
                }

                //
                // calculate the modulus
                //
                n = p.Multiply(q);

                if (n.BitLength != strength)
                {
                    //
                    // if we get here our primes aren't big enough, make the largest
                    // of the two p and try again
                    //
                    p = p.Max(q);
                    continue;
                }

                /*
                 * Require a minimum weight of the NAF representation, since low-weight composites may
	             * be weak against a version of the number-field-sieve for factoring.
	             *
	             * See "The number field sieve for integers of low weight", Oliver Schirokauer.
	             */
                if (WNafUtilities.GetNafWeight(n) < minWeight)
                {
                    p = chooseRandomPrime(pbitlength, e, squaredBound);
                    continue;
                }

                break;
            }

            if (p.CompareTo(q) < 0)
            {
                gcd = p;
                p = q;
                q = gcd;
            }

            pSub1 = p.Subtract(BigInteger.One);
            qSub1 = q.Subtract(BigInteger.One);
            gcd = pSub1.Gcd(qSub1);
            lcm = pSub1.Divide(gcd).Multiply(qSub1);

            //
            // calculate the private exponent
            //
            d = e.ModInverse(lcm);

            if (d.CompareTo(dLowerBound) <= 0)
            {
                continue;
            }
            else
            {
                done = true;
            }

            //
            // calculate the CRT factors
            //
            BigInteger dP, dQ, qInv;

            dP = d.Remainder(pSub1);
            dQ = d.Remainder(qSub1);
            qInv = q.ModInverse(p);

            result = new AsymmetricCipherKeyPair(
                new RsaKeyParameters(false, n, e),
                new RsaPrivateCrtKeyParameters(n, e, d, p, q, dP, dQ, qInv));
        }

        return result;
    }

    /**
     * Choose a random prime value for use with RSA
     *
     * @param bitlength the bit-length of the returned prime
     * @param e         the RSA public exponent
     * @return A prime p, with (p-1) relatively prime to e
     */
    protected BigInteger chooseRandomPrime(int bitlength, BigInteger e, BigInteger sqrdBound)
    {
        for (int i = 0; i != 5 * bitlength; i++)
        {
            BigInteger p = new BigInteger(bitlength, 1, param.Random);

            if (p.Mod(e).Equals(BigInteger.One))
            {
                continue;
            }

            if (p.Multiply(p).CompareTo(sqrdBound) < 0)
            {
                continue;
            }

            if (!isProbablePrime(p))
            {
                continue;
            }

            if (!e.Gcd(p.Subtract(BigInteger.One)).Equals(BigInteger.One))
            {
                continue;
            }

            return p;
        }

        throw new InvalidOperationException("unable to generate prime number for RSA key");
    }

    protected bool isProbablePrime(BigInteger x)
    {
        /*
         * Primes class for FIPS 186-4 C.3 primality checking
         */
        return !Primes.HasAnySmallFactors(x) && Primes.IsMRProbablePrime(x, param.Random, iterations);
    }

    private static int getNumberOfIterations(int bits, int certainty)
    {
        /*
         * NOTE: We enforce a minimum 'certainty' of 100 for bits >= 1024 (else 80). Where the
         * certainty is higher than the FIPS 186-4 tables (C.2/C.3) cater to, extra iterations
         * are added at the "worst case rate" for the excess.
         */
        if (bits >= 1536)
        {
            return certainty <= 100 ? 3
                : certainty <= 128 ? 4
                : 4 + (certainty - 128 + 1) / 2;
        }
        else if (bits >= 1024)
        {
            return certainty <= 100 ? 4
                : certainty <= 112 ? 5
                : 5 + (certainty - 112 + 1) / 2;
        }
        else if (bits >= 512)
        {
            return certainty <= 80 ? 5
                : certainty <= 100 ? 7
                : 7 + (certainty - 100 + 1) / 2;
        }
        else
        {
            return certainty <= 80 ? 40
                : 40 + (certainty - 80 + 1) / 2;
        }
    }
}
}
