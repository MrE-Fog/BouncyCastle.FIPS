using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Operators.Parameters
{
    public class DekInfo
    {
        private readonly string mDekInfo;
        private readonly string mDekAlg;
        private byte[] iv;

        public DekInfo(string dekInfo)
        {
            this.mDekInfo = dekInfo;

            string[] tknz = dekInfo.Split(new char[] { ',' });
            mDekAlg = tknz[0].Trim();

            if (tknz.Length > 1)
            {
                iv = Hex.Decode(tknz[1].Trim());
            }
            else
            {
                iv = null;
            }
        }

        public string Info
        {
            get { return mDekInfo;  }
        }

        public string DekAlgName
        {
            get { return mDekAlg;  }
        }

        public byte[] GetIV()
        {
            return Arrays.Clone(iv);
        }
    }
}
