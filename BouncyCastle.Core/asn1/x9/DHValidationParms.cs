using System;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.X9
{
	public class DHValidationParms
		: Asn1Encodable
	{
		private readonly DerBitString seed;
		private readonly DerInteger pgenCounter;

		public static DHValidationParms GetInstance(Asn1TaggedObject obj, bool isExplicit)
		{
			return GetInstance(Asn1Sequence.GetInstance(obj, isExplicit));
		}

		public static DHValidationParms GetInstance(object obj)
		{
			if (obj is DHDomainParameters)
				return (DHValidationParms)obj;

			if (obj != null)
				return new DHValidationParms(Asn1Sequence.GetInstance(obj));

            return null;
		}

        public DHValidationParms(byte[] seed, BigInteger pgenCounter): this(new DerBitString(seed), new DerInteger(pgenCounter))
        {

        }

        public DHValidationParms(DerBitString seed, DerInteger pgenCounter)
		{
			if (seed == null)
				throw new ArgumentNullException("seed");
			if (pgenCounter == null)
				throw new ArgumentNullException("pgenCounter");

			this.seed = seed;
			this.pgenCounter = pgenCounter;
		}

		private DHValidationParms(Asn1Sequence seq)
		{
			if (seq.Count != 2)
				throw new ArgumentException("Bad sequence size: " + seq.Count, "seq");

			this.seed = DerBitString.GetInstance(seq[0]);
			this.pgenCounter = DerInteger.GetInstance(seq[1]);
		}

		public DerBitString Seed
		{
			get { return this.seed; }
		}

		public DerInteger PgenCounter
		{
			get { return this.pgenCounter; }
		}

		public override Asn1Object ToAsn1Object()
		{
			return new DerSequence(seed, pgenCounter);
		}
	}
}
