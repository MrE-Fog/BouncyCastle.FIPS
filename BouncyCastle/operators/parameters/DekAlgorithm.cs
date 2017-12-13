
namespace Org.BouncyCastle.Operators.Parameters
{
    /// <summary>
    /// OpenSSL supported OpenSSL-PBE algorithms for PEM files.
    /// </summary>
    public class DekAlgorithm
    {
        public static readonly DekAlgorithm Aes128Ecb = new DekAlgorithm("AES-128-ECB");
        public static readonly DekAlgorithm Aes128Cbc = new DekAlgorithm("AES-128-CBC");
        public static readonly DekAlgorithm Aes128Cfb = new DekAlgorithm("AES-128-CFB");
        public static readonly DekAlgorithm Aes128Ofb = new DekAlgorithm("AES-128-OFB");

        public static readonly DekAlgorithm Aes192Ecb = new DekAlgorithm("AES-192-ECB");
        public static readonly DekAlgorithm Aes192Cbc = new DekAlgorithm("AES-192-CBC");
        public static readonly DekAlgorithm Aes192Cfb = new DekAlgorithm("AES-192-CFB");
        public static readonly DekAlgorithm Aes192Ofb = new DekAlgorithm("AES-192-OFB");

        public static readonly DekAlgorithm Aes256Ecb = new DekAlgorithm("AES-256-ECB");
        public static readonly DekAlgorithm Aes256Cbc = new DekAlgorithm("AES-256-CBC");
        public static readonly DekAlgorithm Aes256Cfb = new DekAlgorithm("AES-256-CFB");
        public static readonly DekAlgorithm Aes256Ofb = new DekAlgorithm("AES-256-OFB");

        public static readonly DekAlgorithm TwoKeyTripleDesEcb = new DekAlgorithm("DES-EDE-ECB");
        public static readonly DekAlgorithm TwoKeyTripleDesCbc = new DekAlgorithm("DES-EDE-CBC");
        public static readonly DekAlgorithm TwoKeyTripleDesCfb = new DekAlgorithm("DES-EDE-CFB");
        public static readonly DekAlgorithm TwoKeyTripleDesOfb = new DekAlgorithm("DES-EDE-OFB");

        public static readonly DekAlgorithm ThreeKeyTripleDesEcb = new DekAlgorithm("DES-EDE3-ECB");
        public static readonly DekAlgorithm ThreeKeyTripleDesCbc = new DekAlgorithm("DES-EDE3-CBC");
        public static readonly DekAlgorithm ThreeKeyTripleDesCfb = new DekAlgorithm("DES-EDE3-CFB");
        public static readonly DekAlgorithm ThreeKeyTripleDesOfb = new DekAlgorithm("DES-EDE3-OFB");

        private readonly string mName;

        private DekAlgorithm(string name)
        {
            this.mName = name;
        }

        public string Name
        {
            get
            {
                return mName;
            }
        }
    }
}
