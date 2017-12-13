using Org.BouncyCastle.Asn1.Cms;
using System.Collections.Generic;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// General class for generating a CMS enveloped-data message.
    /// </summary>
    public class CmsEnvelopedGenerator
    {
        protected readonly IList<IRecipientInfoGenerator> recipientInfoGenerators = new List<IRecipientInfoGenerator>();

        protected ICmsAttributeTableGenerator unprotectedAttributeGenerator = null;
        protected OriginatorInfo originatorInfo;

        /**
         * base constructor
         */
        public CmsEnvelopedGenerator()
        {
        }

        public void SetUnprotectedAttributeGenerator(ICmsAttributeTableGenerator unprotectedAttributeGenerator)
        {
            this.unprotectedAttributeGenerator = unprotectedAttributeGenerator;
        }

        public void SetOriginatorInfo(OriginatorInformation originatorInfo)
        {
            this.originatorInfo = originatorInfo.ToAsn1Structure();
        }

        /**
         * Add a generator to produce the recipient info required.
         * 
         * @param recipientGenerator a generator of a recipient info object.
         */
        public void AddRecipientInfoGenerator(IRecipientInfoGenerator recipientGenerator)
        {
            recipientInfoGenerators.Add(recipientGenerator);
        }
    }
}
