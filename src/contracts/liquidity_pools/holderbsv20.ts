import { BSV20V1 } from 'scrypt-ord';
import { assert, ByteString, hash256, method, prop } from 'scrypt-ts';
import { TxUtil } from '../txUtil';

/**
 * Holds a BSV20 token for use in a liquidity pool.
 * Ensures that the relevant input's match the position and txid's of the outputs
 * Relocking is handled by the main contract
 */
export class LPHolderBSV20 extends BSV20V1 {
    @prop(false)
    readonly pos: bigint;

    constructor(tick: ByteString, max: bigint, lim: bigint, dec: bigint, pos: bigint) {
        super(tick, max, lim, dec);
        this.init(...arguments);
        this.pos = pos;
    }
    
    @method()
    public unlock() {
        assert(
            TxUtil.unlockHolder(
                this.prevouts, 
                this.ctx.utxo.outpoint.outputIndex, 
                this.pos, 
                this.ctx.utxo.outpoint.txid,
            )
        );
    }
}