import {
    ByteString,
    Constants,
    SmartContractLib,
    Utils,
    assert,
    method,
    slice,
    toByteString,
} from 'scrypt-ts'

type Output = {
    satoshis: bigint
    script: ByteString
}

export class TxUtil extends SmartContractLib {
    static readonly MAX_INPUTS_OUTPUTS_READ_OUTPUT: bigint = 32n;

    // get i-th outpoint's txid
    @method()
    static getPrevoutTxid(prevouts: ByteString, i: bigint): ByteString {
        let offset: bigint = i * Constants.OutpointLen
        return slice(prevouts, offset, offset + Constants.TxIdLen)
    }

    // Unlocks the token/coin holders for liquidity pools
    @method()
    static unlockHolder(
        prevouts: ByteString, 
        outputIndex: bigint, 
        pos: bigint, 
        txid: ByteString
    ): boolean {
        // Validate that the input is the same position as the output
        assert(outputIndex === pos, 'incorrect output position');

        // Validate input 0
        const inputTxid: ByteString = txid;
        assert(TxUtil.getPrevoutTxid(prevouts, 0n) === inputTxid, 'input 0 is not from correct transaction');

        // Validate other output
        let assertPos: bigint = 1n;
        if (pos === 1n) {
            assertPos = 2n;
        }

        assert(TxUtil.getPrevoutTxid(prevouts, assertPos) === inputTxid, 'other input is not from correct transaction');

        return true;
    }

    // get i-th outpoint's output index
    @method()
    static getPrevoutOutputIdx(prevouts: ByteString, i: bigint): bigint {
        let offset = i * Constants.OutpointLen
        return Utils.fromLEUnsigned(
            slice(
                prevouts,
                offset + Constants.TxIdLen,
                offset + Constants.OutpointLen
            )
        )
    }

    @method()
    static readOutput(tx: ByteString, outputIndex: bigint): Output {
        // first 4 bytes version
        // 1 byte input num
        let pos: bigint = 4n
        let ninputs: bigint = Utils.fromLEUnsigned(slice(tx, pos, pos + 1n))
        pos = pos + 1n
        let script: ByteString = toByteString('')
        let satoshis: bigint = 0n
        // input
        assert(ninputs <= TxUtil.MAX_INPUTS_OUTPUTS_READ_OUTPUT)
        for (let i = 0; i < TxUtil.MAX_INPUTS_OUTPUTS_READ_OUTPUT; i++) {
            if (i < ninputs) {
                // output point 36 bytes
                pos = pos + 36n
                // 1 byte var
                // script code + 4 bytes sequence
                let varLen: bigint = Utils.fromLEUnsigned(
                    slice(tx, pos, pos + 1n)
                )
                if (varLen < 253) {
                    let scriptLen: bigint = varLen
                    pos = pos + 1n + scriptLen + 4n
                } else if (varLen == 253n) {
                    let scriptLen: bigint = Utils.fromLEUnsigned(
                        slice(tx, pos + 1n, pos + 3n)
                    )
                    pos = pos + 3n + scriptLen + 4n
                } else if (varLen == 254n) {
                    let scriptLen: bigint = Utils.fromLEUnsigned(
                        slice(tx, pos + 1n, pos + 5n)
                    )
                    pos = pos + 5n + scriptLen + 4n
                } else {
                    let scriptLen: bigint = Utils.fromLEUnsigned(
                        slice(tx, pos + 1n, pos + 9n)
                    )
                    pos = pos + 9n + scriptLen + 4n
                }
            }
        }

        let noutputs: bigint = Utils.fromLEUnsigned(slice(tx, pos, pos + 1n))
        pos = pos + 1n
        assert(noutputs <= TxUtil.MAX_INPUTS_OUTPUTS_READ_OUTPUT)
        for (let i = 0n; i < TxUtil.MAX_INPUTS_OUTPUTS_READ_OUTPUT; i++) {
            if (i < noutputs) {
                // 8 bytes value
                let sats: bigint = Utils.fromLEUnsigned(
                    slice(tx, pos, pos + 8n)
                )
                pos = pos + 8n
                // script code
                let varLen: bigint = Utils.fromLEUnsigned(
                    slice(tx, pos, pos + 1n)
                )
                let scriptLen: bigint = 0n
                if (varLen < 253n) {
                    scriptLen = varLen
                    pos = pos + 1n + scriptLen
                } else if (varLen == 253n) {
                    scriptLen = Utils.fromLEUnsigned(
                        slice(tx, pos + 1n, pos + 3n)
                    )
                    pos = pos + 3n + scriptLen
                } else if (varLen == 254n) {
                    scriptLen = Utils.fromLEUnsigned(
                        slice(tx, pos + 1n, pos + 5n)
                    )
                    pos = pos + 5n + scriptLen
                } else {
                    scriptLen = Utils.fromLEUnsigned(
                        slice(tx, pos + 1n, pos + 9n)
                    )
                    pos = pos + 9n + scriptLen
                }
                if (i == outputIndex) {
                    script = slice(tx, pos - scriptLen, pos)
                    satoshis = sats
                }
            }
        }

        // 4 bytes locktime
        return { satoshis, script }
    }
}
