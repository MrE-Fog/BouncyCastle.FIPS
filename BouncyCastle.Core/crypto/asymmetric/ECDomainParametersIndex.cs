using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Internal.EC;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
	public class ECDomainParametersIndex
	{
		/**
	     * Retrieve an EC based domain parameter by OID. A custom curve will be returned if one is available.
	     *
	     * @param paramOid object identifier for the domain parameters.
	     * @return the matching domain parameters if found, null otherwise.
	     */
		public static NamedECDomainParameters LookupDomainParameters(DerObjectIdentifier paramOid)
		{
			X9ECParameters rv = CustomNamedCurves.GetByOid(paramOid);

			if (rv == null)
			{
				rv = ECNamedCurveTable.GetByOid(paramOid);
			}

			if (rv != null)
			{
				return new NamedECDomainParameters(paramOid, rv.Curve, rv.G, rv.N, rv.H, rv.GetSeed());
			}

			return null;
		}

		/**
	     * Retrieve an EC based domain parameter by parameter ID. A custom curve will be returned if one is available.
	     *
	     * @param paramID identifier for the domain parameters.
	     * @return the matching domain parameters if found, null otherwise.
	     */
		public static NamedECDomainParameters LookupDomainParameters(IECDomainParametersID paramID)
		{
			X9ECParameters rv = CustomNamedCurves.GetByName(paramID.CurveName);

			if (rv == null)
			{
				rv = ECNamedCurveTable.GetByName(paramID.CurveName);
			}

			if (rv != null)
			{
				return new NamedECDomainParameters(ECNamedCurveTable.GetOid(paramID.CurveName), rv.Curve, rv.G, rv.N, rv.H, rv.GetSeed());
			}

			return null;
		}

		public static DerObjectIdentifier LookupOid(ECDomainParameters domainParameters)
		{
			/*
			for (Enumeration<String> en = (Enumeration<String>)ECNamedCurveTable.getNames(); en.hasMoreElements();)
			{
				string name = en.nextElement();
				X9ECParameters rv = ECNamedCurveTable.getByName(name);

				if (rv.getN().equals(domainParameters.getN()))
				{
					ECDomainParameters params = lookupDomainParameters(new ECDomainParametersID()
						{
							public String getCurveName()
							{
								return name;
							}
						});
					if (params.equals(domainParameters))
					{
						return ECNamedCurveTable.getOID(name);
					}
				}
			}
*/
			return null;
		}
	}
}

