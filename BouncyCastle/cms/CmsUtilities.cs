using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Cms
{
    internal class CmsUtilities
    {
		// TODO Is there a .NET equivalent to this?
//		private static readonly Runtime RUNTIME = Runtime.getRuntime();

		internal static int MaximumMemory
		{
			get
			{
				// TODO Is there a .NET equivalent to this?
				long maxMem = int.MaxValue;//RUNTIME.maxMemory();

				if (maxMem > int.MaxValue)
				{
					return int.MaxValue;
				}

				return (int)maxMem;
			}
		}

		internal static ContentInfo ReadContentInfo(
			byte[] input)
		{
			// enforce limit checking as from a byte array
			return ReadContentInfo(new Asn1InputStream(input));
		}

		internal static ContentInfo ReadContentInfo(
			Stream input)
		{
			// enforce some limit checking
			return ReadContentInfo(new Asn1InputStream(input, MaximumMemory));
		}

		private static ContentInfo ReadContentInfo(
			Asn1InputStream aIn)
		{
			try
			{
				return ContentInfo.GetInstance(aIn.ReadObject());
			}
			catch (IOException e)
			{
				throw new CmsException("IOException reading content.", e);
			}
			catch (InvalidCastException e)
			{
				throw new CmsException("Malformed content.", e);
			}
			catch (ArgumentException e)
			{
				throw new CmsException("Malformed content.", e);
			}
		}

		public static byte[] StreamToByteArray(
            Stream inStream)
        {
			return Streams.ReadAll(inStream);
        }

		public static byte[] StreamToByteArray(
            Stream	inStream,
			int		limit)
        {
			return Streams.ReadAllLimited(inStream, limit);
        }

		public static IList GetCertificatesFromStore(
			IStore<X509Certificate> certStore)
		{
			try
			{
				IList certs = Platform.CreateArrayList();

				if (certStore != null)
				{
					foreach (X509Certificate c in certStore.GetMatches(null))
					{
						certs.Add(
							X509CertificateStructure.GetInstance(
								Asn1Object.FromByteArray(c.GetEncoded())));
					}
				}

				return certs;
			}
			catch (CertificateEncodingException e)
			{
				throw new CmsException("error encoding certs", e);
			}
			catch (Exception e)
			{
				throw new CmsException("error processing certs", e);
			}
		}

        internal static AlgorithmIdentifier fixAlgID(AlgorithmIdentifier algId)
        {
            if (algId.Parameters == null)
            {
                return new AlgorithmIdentifier(algId.Algorithm, DerNull.Instance);
            }

            return algId;
        }

        public static IList GetCrlsFromStore(
			IStore<X509Crl> crlStore)
		{
			try
			{
                IList crls = Platform.CreateArrayList();

				if (crlStore != null)
				{
					foreach (X509Crl c in crlStore.GetMatches(null))
					{
						crls.Add(
							CertificateList.GetInstance(
								Asn1Object.FromByteArray(c.GetEncoded())));
					}
				}

				return crls;
			}
			catch (CrlException e)
			{
				throw new CmsException("error encoding crls", e);
			}
			catch (Exception e)
			{
				throw new CmsException("error processing crls", e);
			}
		}

		public static Asn1Set CreateBerSetFromList(
			IList berObjects)
		{
			Asn1EncodableVector v = new Asn1EncodableVector();

			foreach (Asn1Encodable ae in berObjects)
			{
				v.Add(ae);
			}

			return new BerSet(v);
		}

		public static Asn1Set CreateDerSetFromList(
			IList derObjects)
		{
			Asn1EncodableVector v = new Asn1EncodableVector();

			foreach (Asn1Encodable ae in derObjects)
			{
				v.Add(ae);
			}

			return new DerSet(v);
		}

		internal static Stream CreateBerOctetOutputStream(Stream s, int tagNo, bool isExplicit, int bufferSize)
		{
			BerOctetStringGenerator octGen = new BerOctetStringGenerator(s, tagNo, isExplicit);
			return octGen.GetOctetOutputStream(bufferSize);
		}

		internal static TbsCertificateStructure GetTbsCertificateStructure(X509Certificate cert)
		{
			return TbsCertificateStructure.GetInstance(Asn1Object.FromByteArray(cert.GetTbsCertificate()));
		}

		internal static IssuerAndSerialNumber GetIssuerAndSerialNumber(X509Certificate cert)
		{
			TbsCertificateStructure tbsCert = GetTbsCertificateStructure(cert);
			return new IssuerAndSerialNumber(tbsCert.Issuer, tbsCert.SerialNumber.Value);
		}

        internal static bool IsEquivalent(AlgorithmIdentifier algId1, AlgorithmIdentifier algId2)
        {
            if (algId1 == null || algId2 == null)
            {
                return false;
            }

            if (!algId1.Algorithm.Equals(algId2.Algorithm))
            {
                return false;
            }

            Asn1Encodable params1 = algId1.Parameters;
            Asn1Encodable params2 = algId2.Parameters;
            if (params1 != null)
            {
                return params1.Equals(params2) || (params1.Equals(DerNull.Instance) && params2 == null);
            }

            return params2 == null || params2.Equals(DerNull.Instance);
        }

        internal static Stream attachDigestsToInputStream(ICollection digests, Stream s)
        {
            Stream result = s;
            IEnumerator it = digests.GetEnumerator();
            while (it.MoveNext())
            {
                IStreamCalculator<IBlockResult> digest = (IStreamCalculator<IBlockResult>)it.Current;
                result = new TeeInputStream(result, digest.Stream);
            }
            return result;
        }

        internal static Stream attachSignersToOutputStream(ICollection signers, Stream s)
        {
            Stream result = s;
            IEnumerator it = signers.GetEnumerator();
            while (it.MoveNext())
            {
                SignerInfoGenerator signerGen = (SignerInfoGenerator)it.Current;
                result = getSafeTeeOutputStream(result, signerGen.GetCalculatingOutputStream());
            }
            return result;
        }

        internal static Stream getSafeOutputStream(Stream s)
        {
            return s == null ? new NullOutputStream() : s;
        }

        internal static Stream getSafeTeeOutputStream(Stream s1,
                Stream s2)
        {
            return s1 == null ? getSafeOutputStream(s2)
                    : s2 == null ? getSafeOutputStream(s1) : new TeeOutputStream(
                            s1, s2);
        }

        internal class NullOutputStream: BaseOutputStream
        {
            public override void WriteByte(byte b)
            {
                // do nothing
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                // do nothing
            }
        }
    }
}
