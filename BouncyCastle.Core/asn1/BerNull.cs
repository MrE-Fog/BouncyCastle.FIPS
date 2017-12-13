using System;

namespace Org.BouncyCastle.Asn1
{
	/**
	 * A BER Null object.
	 */
	public class BerNull
		: DerNull
	{
		public static new readonly BerNull Instance = new BerNull();

        protected internal BerNull()
            : base()
		{
		}

		internal override void Encode(
			DerOutputStream  derOut)
		{
			if (derOut is Asn1OutputStream || derOut is BerOutputStream)
			{
				derOut.WriteByte(Asn1Tags.Null);
			}
			else
			{
				base.Encode(derOut);
			}
		}
	}
}
