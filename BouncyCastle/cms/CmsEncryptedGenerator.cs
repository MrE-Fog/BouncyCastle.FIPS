using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Cms
{
    public class CmsEncryptedGenerator
    {
        protected ICmsAttributeTableGenerator unprotectedAttributeGenerator = null;

        /**
         * base constructor
         */
        protected CmsEncryptedGenerator()
        {
        }

        public void SetUnprotectedAttributeGenerator(ICmsAttributeTableGenerator unprotectedAttributeGenerator)
        {
            this.unprotectedAttributeGenerator = unprotectedAttributeGenerator;
        }
    }
}
