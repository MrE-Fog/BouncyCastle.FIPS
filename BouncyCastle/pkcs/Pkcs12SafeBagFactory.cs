using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using System;

namespace Org.BouncyCastle.Pkcs
{
    public class Pkcs12SafeBagFactory
    {
        private Asn1Sequence safeBagSeq;

        public Pkcs12SafeBagFactory(ContentInfo info)
        {
            if (info.ContentType.Equals(PkcsObjectIdentifiers.EncryptedData))
            {
                throw new ArgumentException("encryptedData requires constructor with decryptor.");
            }

            this.safeBagSeq = Asn1Sequence.GetInstance(Asn1OctetString.GetInstance(info.Content).GetOctets());
        }

        public Pkcs12SafeBagFactory(ContentInfo info, IDecryptorBuilderProvider<AlgorithmIdentifier> inputDecryptorProvider)
        {
            if (info.ContentType.Equals(PkcsObjectIdentifiers.EncryptedData))
            {
                CmsEncryptedData encData = new CmsEncryptedData(Org.BouncyCastle.Asn1.Cms.ContentInfo.GetInstance(info));

                try
                {
                    this.safeBagSeq = Asn1Sequence.GetInstance(encData.GetContent(inputDecryptorProvider));
                }
                catch (CmsException e)
                {
                    throw new PkcsException("unable to extract data: " + e.Message, e);
                }
                return;
            }

            throw new ArgumentException("encryptedData requires constructor with decryptor.");
        }

        public Pkcs12SafeBag[] GetSafeBags()
        {
            Pkcs12SafeBag[] safeBags = new Pkcs12SafeBag[safeBagSeq.Count];

            for (int i = 0; i != safeBagSeq.Count; i++)
            {
                safeBags[i] = new Pkcs12SafeBag(SafeBag.GetInstance(safeBagSeq[i]));
            }

            return safeBags;
        }
    }
}
