
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1.Cms;

namespace Org.BouncyCastle.Cms
{
    internal class CmsEnvelopedHelper
    {
        internal static RecipientInformationStore BuildRecipientInformationStore(
            Asn1Set recipientInfos, AlgorithmIdentifier messageAlgorithm, ICmsSecureReadable secureReadable)
        {
            return BuildRecipientInformationStore(recipientInfos, messageAlgorithm, secureReadable, null);
        }

        internal static RecipientInformationStore BuildRecipientInformationStore(
            Asn1Set recipientInfos, AlgorithmIdentifier messageAlgorithm, ICmsSecureReadable secureReadable, IAuthAttributesProvider additionalData)
        {
            IList<RecipientInformation> infos = new List<RecipientInformation>();
            for (int i = 0; i != recipientInfos.Count; i++)
            {
                RecipientInfo info = RecipientInfo.GetInstance(recipientInfos[i]);

                readRecipientInfo(infos, info, messageAlgorithm, secureReadable, additionalData);
            }
            return new RecipientInformationStore(infos);
        }

        private static void readRecipientInfo(IList<RecipientInformation> infos, RecipientInfo info, AlgorithmIdentifier messageAlgorithm, ICmsSecureReadable secureReadable, IAuthAttributesProvider additionalData)
        {
            Asn1Encodable recipInfo = info.Info;
            if (recipInfo is KeyTransRecipientInfo)
            {
                infos.Add(new KeyTransRecipientInformation(
                    (KeyTransRecipientInfo)recipInfo, messageAlgorithm, secureReadable, additionalData));
            }
            /*
            else if (recipInfo is KEKRecipientInfo)
            {
                infos.Add(new KEKRecipientInformation(
                    (KEKRecipientInfo)recipInfo, messageAlgorithm, secureReadable, additionalData));
            }
            else if (recipInfo is KeyAgreeRecipientInfo)
            {
                KeyAgreeRecipientInformation.readRecipientInfo(infos,
                    (KeyAgreeRecipientInfo)recipInfo, messageAlgorithm, secureReadable, additionalData);
            }
            else if (recipInfo is PasswordRecipientInfo)
            {
                infos.Add(new PasswordRecipientInformation(
                    (PasswordRecipientInfo)recipInfo, messageAlgorithm, secureReadable, additionalData));
            }*/
        }

        internal class CmsEnvelopedSecureReadable : ICmsSecureReadable
        {
            private AlgorithmIdentifier encAlg;
            private CmsReadable readable;

            public CmsEnvelopedSecureReadable(AlgorithmIdentifier encAlg, CmsReadable readable)
            {
                this.encAlg = encAlg;
                this.readable = readable;
            }

            public Stream GetInputStream()
            {
                return readable.GetInputStream();
            }
        }
    }
}