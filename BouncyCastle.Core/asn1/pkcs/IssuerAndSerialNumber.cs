using System;

using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class IssuerAndSerialNumber
        : Asn1Encodable
    {
        private readonly X500Name name;
        private readonly DerInteger certSerialNumber;

		public static IssuerAndSerialNumber GetInstance(
            object obj)
        {
            if (obj is IssuerAndSerialNumber)
                return (IssuerAndSerialNumber)obj;

            if (obj != null)
                return new IssuerAndSerialNumber(Asn1Sequence.GetInstance(obj));

            return null;
        }

		private IssuerAndSerialNumber(
            Asn1Sequence seq)
        {
			if (seq.Count != 2)
				throw new ArgumentException("Wrong number of elements in sequence", "seq");

			this.name = X500Name.GetInstance(seq[0]);
            this.certSerialNumber = DerInteger.GetInstance(seq[1]);
        }

		public IssuerAndSerialNumber(
            X500Name	name,
            BigInteger	certSerialNumber)
        {
            this.name = name;
            this.certSerialNumber = new DerInteger(certSerialNumber);
        }

		public IssuerAndSerialNumber(
            X500Name	name,
            DerInteger	certSerialNumber)
        {
            this.name = name;
            this.certSerialNumber = certSerialNumber;
        }

		public X500Name Name
		{
			get { return name; }
		}

		public DerInteger CertificateSerialNumber
		{
			get { return certSerialNumber; }
		}

		public override Asn1Object ToAsn1Object()
        {
			return new DerSequence(name, certSerialNumber);
        }
    }
}
