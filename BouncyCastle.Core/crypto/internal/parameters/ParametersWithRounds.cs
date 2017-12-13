using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Crypto.Internal.Parameters
{
    internal class ParametersWithRounds: ICipherParameters
    {
        private readonly ICipherParameters parameters;
        private readonly int rounds;

        internal ParametersWithRounds(ICipherParameters parameters, int rounds)
        {
            this.parameters = parameters;
            this.rounds = rounds;
        }

        internal int Rounds
        {
            get { return rounds; }
        }

        internal ICipherParameters Parameters
        {
            get { return parameters; }
        }
    }

}
