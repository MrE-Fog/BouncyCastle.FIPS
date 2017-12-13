using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Utilities.Test
{
    public class TestRandomEntropySourceProvider: IEntropySourceProvider
    {
        private readonly SecureRandom _sr;
        private readonly bool _predictionResistant;

        /**
         * Create a test entropy source provider.
         *
         * @param isPredictionResistant boolean indicating if the SecureRandom is based on prediction resistant entropy or not (true if it is).
         */
        public TestRandomEntropySourceProvider(bool isPredictionResistant)
        {
            _sr = new SecureRandom();
            _predictionResistant = isPredictionResistant;
        }

        /**
         * Return an entropy source that will create bitsRequired bits of entropy on
         * each invocation of getEntropy().
         *
         * @param bitsRequired size (in bits) of entropy to be created by the provided source.
         * @return an EntropySource that generates bitsRequired bits of entropy on each call to its getEntropy() method.
         */
        public IEntropySource Get(int bitsRequired)
        {
            return new TestEntropySource(_sr, bitsRequired, _predictionResistant);
        }

        private class TestEntropySource : IEntropySource
        {
            private readonly SecureRandom sr;
            private readonly int bitsRequired;
            private bool isPredictionResistant;

            internal TestEntropySource(SecureRandom sr, int bitsRequired, bool isPredictionResistant)
            {
                this.sr = sr;
                this.bitsRequired = bitsRequired;
                this.isPredictionResistant = isPredictionResistant;
            }

            public bool IsPredictionResistant
            {
                get
                {
                    return isPredictionResistant;
                }
            }

            public byte[] GetEntropy()
            {
                byte[] rv = new byte[(bitsRequired + 7) / 8];

                sr.NextBytes(rv);

                return rv;
            }

            public int EntropySize
            {
                get
                {
                    return bitsRequired;
                }
            }
        }
    }

}
